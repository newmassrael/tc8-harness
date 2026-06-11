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

#include "tcp_flags_processing_07_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing07SM =
    ::SCE::Generated::tcp_flags_processing_07::tcp_flags_processing_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing07SM>
    : TcpAnyBase<cases::TcpFlagsProcessing07SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT / CLOSING / LAST-ACK / TIME-WAIT MUST "
        "ignore any segment with only URG flag set (RFC 793 §3.9 p74 "
        "Event Processing). 4 spec iterations exercise wst ∈ "
        "{CW, CLOSING, LA, TW}";

    // Phase 1 CW prelude is the SCXML's initial state, so its
    // stimulus runs synchronously in the body. Phases 2..4 schedule
    // via scheduleAfterStateEntry on each phase's handshake_ack
    // state — required because each prior phase's 3 s absence is
    // wall-clock; a synchronous all-phases-up-front stimulus would
    // queue all events into pcap before SCXML reaches the later
    // phase's state, and the prior absence would drain the events
    // (FLAGS_INVALID_15-style multi-phase absence pattern).
    //
    // Per-phase port quads dodge BASICS_11/12/13/14, FLAGS_INVALID_14,
    // UNACCEPTABLE_13 (default +0 quad) and the §4.8 active-OPEN
    // cluster's existing reservations (+0..+6 case 15, +20..+25 cases 03..06,
    // +30..+38 HEADER, +40..+41 MSS_OPTIONS, +50/+51/+52 cases 11/06/08).
    //
    // URG-only segment shape: flags = kTcpFlagUrg only (no ACK / SYN
    // / RST / FIN). seq_num = tester's snd_nxt at probe time =
    // DUT's rcv_nxt = in-window expected next byte. The
    // urgent_pointer field defaults to 0 — Linux's
    // tcp_validate_incoming drops the segment at the early
    // `if (!th->ack)` check before any urgent-pointer handling.
    //
    // Per-phase scope notes:
    //   * Phase 1 CW: tester shutdown(WR) → DUT CW. No AckDrop /
    //     RstDrop needed (tester listener still owns the FW2 socket;
    //     no spurious tester emits).
    //   * Phase 2 CLOSING: TesterAutoAckDrop scoped inside the lambda
    //     (driveCloseToClosing requires it). silentlyCloseTesterFd
    //     after URG inject leaves the 4-tuple clean.
    //   * Phase 3 LA: TesterAutoAckDrop scoped inside the lambda so
    //     the DUT FIN's tester auto-ACK is suppressed and DUT stays
    //     in LA across the URG inject. silentlyCloseTesterFd after.
    //   * Phase 4 TW: driveTcpToTimeWaitFw2 closes tester_fd
    //     internally; URG inject + 3 s absence runs after with no
    //     tester socket on the 4-tuple. URG-only is silent in TW
    //     per Linux's tcp_timewait_state_process (no ACK → no
    //     rate-limit challenge ACK).
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
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p4_handshake_ack),
            [iface_copy, cfg_copy, dut_mac]() {
                runPhase4TimeWait(cfg_copy, iface_copy);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_p1_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase1_cw";
            case State::Fail_p1_no_close_wait_ack:           return "fail:no_dut_close_wait_ack_phase1_cw";
            case State::Fail_p1_unexpected_response:         return "fail:dut_emitted_response_to_urg_only_in_cw";
            case State::Fail_p2_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase2_closing";
            case State::Fail_p2_no_dut_fin:                  return "fail:no_dut_fin_phase2_closing";
            case State::Fail_p2_no_closing_ack:              return "fail:no_dut_closing_ack_phase2_closing";
            case State::Fail_p2_unexpected_response:         return "fail:dut_emitted_response_to_urg_only_in_closing";
            case State::Fail_p3_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase3_la";
            case State::Fail_p3_no_close_wait_ack:           return "fail:no_dut_close_wait_ack_phase3_la";
            case State::Fail_p3_no_dut_fin:                  return "fail:no_dut_fin_phase3_la";
            case State::Fail_p3_unexpected_response:         return "fail:dut_emitted_response_to_urg_only_in_la";
            case State::Fail_p4_no_handshake_ack:            return "fail:no_dut_handshake_ack_phase4_tw";
            case State::Fail_p4_no_dut_fin:                  return "fail:no_dut_fin_phase4_tw";
            case State::Fail_p4_no_tester_fin_ack:           return "fail:no_dut_tester_fin_ack_phase4_tw";
            case State::Fail_p4_unexpected_response:         return "fail:dut_emitted_response_to_urg_only_in_tw";
            default:                                         return "running";
        }
    }

private:
    // URG-only segment with caller-supplied seq (the kernel-view of
    // tester's next-byte = DUT's rcv_nxt = in-window).
    static void emitUrgOnly(const ::tc8::TestConfig& cfg,
                            std::string_view iface,
                            std::uint16_t src_port,
                            std::uint16_t dst_port,
                            std::uint32_t seq_value) {
        ::tc8::stimulus::TcpSegmentSpec urg{};
        urg.src_port = src_port;
        urg.dst_port = dst_port;
        urg.seq_num  = seq_value;
        urg.ack_num  = 0U;
        urg.flags    = ::tc8::stimulus::kTcpFlagUrg;
        ::tc8::sce::tcp::emitTcpFrame(
            cfg, iface, cfg.dut.mac, urg,
            /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1CloseWait(const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 53U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 53U;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        seq_range->snd_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase2Closing(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 54U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 54U;

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
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        info.tester_seq_post_fin);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase3LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 55U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 55U;

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
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        seq_range->snd_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase4TimeWait(const ::tc8::TestConfig& cfg,
                                  std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 56U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 56U;

        const auto info = driveTcpToTimeWaitFw2(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/7, /*close_req_id=*/8, /*socket_id=*/4,
            local_port, remote_port);
        if (info.ok) {
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        info.tester_seq_post_fin);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing07SM, tcp_flags_processing_07)
