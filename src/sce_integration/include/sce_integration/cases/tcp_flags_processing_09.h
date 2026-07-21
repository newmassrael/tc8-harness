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
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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
    static constexpr std::string_view kDescription  =
        "TCP in CLOSE-WAIT / CLOSING / LAST-ACK MUST not change "
        "state after receiving a FIN+ACK (RFC 793 §3.9 p75 Event "
        "Processing). 3 spec iterations exercise wst ∈ "
        "{CW with valid ack, CLOSING with invalid ack, LA with "
        "invalid ack}";

    // Migrated onto the Tier-2 DUT-control seam: every phase's active
    // OPEN runs through driveSeamActiveOpen, the CLOSING DUT CLOSE
    // through driveSeamCloseToClosing, and the LAST-ACK DUT CLOSE
    // through closeTcp, so the case runs unchanged on whichever backend
    // --dut-control selected. The deferred phases capture the
    // CLI-owned IDutControl by pointer (it outlives the scheduled
    // callbacks); the tester-side FIN / dup-FIN raw inject stays
    // case-owned.
    //
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
    // .tester_seq_post_fin - 1 from driveSeamCloseToClosing). The
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
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1CloseWait(dut, cfg, iface);

        std::string             iface_copy(iface);
        ::tc8::TestConfig       cfg_copy = cfg;
        ::tc8::sce::IDutControl* dut_ptr = &dut;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [dut_ptr, iface_copy, cfg_copy]() {
                runPhase2Closing(*dut_ptr, cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [dut_ptr, iface_copy, cfg_copy]() {
                runPhase3LastAck(*dut_ptr, cfg_copy, iface_copy);
            });
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

    static void runPhase1CloseWait(::tc8::sce::IDutControl& dut,
                                   const ::tc8::TestConfig& cfg,
                                   std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing09Phase1LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing09Phase1LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            // Replay original tester FIN: seq = snd_nxt - 1 (the FIN
            // consumed +1 to advance snd_nxt; the original FIN's seq
            // was snd_nxt - 1). ack = valid (rcv_nxt = DUT's
            // post-handshake snd_nxt; DUT has not sent FIN since the
            // DUT was never closed).
            emitDupFinAck(cfg, iface, remote_port, local_port,
                          seq_range->snd_nxt - 1U,
                          seq_range->rcv_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase2Closing(::tc8::sce::IDutControl& dut,
                                 const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing09Phase2LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing09Phase2LocalOffset;

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

    static void runPhase3LastAck(::tc8::sce::IDutControl& dut,
                                 const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing09Phase3LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing09Phase3LocalOffset;

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
        // DUT close (seam closeTcp) → DUT CW→LAST-ACK; AckDrop holds
        // the tester auto-ACK so the DUT stays in LAST-ACK.
        dut.tcpControl()->closeTcp(open.conn->socket);
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
