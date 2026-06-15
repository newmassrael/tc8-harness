#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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

    // Migrated onto the Tier-2 DUT-control seam: every phase's DUT
    // drive (active OPEN, DUT CLOSE to CLOSING, DUT CLOSE to LAST-ACK,
    // FIN-WAIT-2 TIME-WAIT prelude) runs through the seam wrappers
    // (driveSeamActiveOpen / driveSeamCloseToClosing / closeTcp /
    // driveSeamTimeWaitFw2), so the case runs unchanged on whichever
    // backend --dut-control selected. The tester-side shutdown(WR),
    // AckDrop, URG-only raw-inject, and silent dispose stay case-owned.
    // The deferred-phase lambdas capture an IDutControl* (CLI-owned,
    // outlives the scheduler callbacks) as in FLAGS_PROCESSING_09.
    //
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
    //     (driveSeamCloseToClosing requires it). silentlyCloseTesterFd
    //     after URG inject leaves the 4-tuple clean.
    //   * Phase 3 LA: TesterAutoAckDrop scoped inside the lambda so
    //     the DUT FIN's tester auto-ACK is suppressed and DUT stays
    //     in LA across the URG inject. silentlyCloseTesterFd after.
    //   * Phase 4 TW: driveSeamTimeWaitFw2 closes tester_fd
    //     internally; URG inject + 3 s absence runs after with no
    //     tester socket on the 4-tuple. URG-only is silent in TW
    //     per Linux's tcp_timewait_state_process (no ACK → no
    //     rate-limit challenge ACK).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1CloseWait(cfg, iface, dut);

        std::string           iface_copy(iface);
        ::tc8::TestConfig     cfg_copy = cfg;
        ::tc8::sce::IDutControl* dut_ptr = &dut;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase2Closing(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase3LastAck(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p4_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase4TimeWait(cfg_copy, iface_copy, *dut_ptr);
            });
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
                                   std::string_view iface,
                                   ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 53U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 53U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
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
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 54U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 54U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        const auto info = driveSeamCloseToClosing(
            dut, cfg, iface, tester_fd, open.conn->socket,
            local_port, remote_port);
        if (info.ok) {
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        info.tester_seq_post_fin);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase3LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 55U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 55U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        seq_range->snd_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase4TimeWait(const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 56U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 56U;

        const auto info = driveSeamTimeWaitFw2(
            dut, cfg, local_port, remote_port);
        if (info.ok) {
            emitUrgOnly(cfg, iface, remote_port, local_port,
                        info.tester_seq_post_fin);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing07SM, tcp_flags_processing_07)
