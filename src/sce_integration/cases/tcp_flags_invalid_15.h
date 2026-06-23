#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_15_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid15SM = ::SCE::Generated::tcp_flags_invalid_15::tcp_flags_invalid_15;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid15SM>
    : TcpAnyBase<cases::TcpFlagsInvalid15SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_15";
    static constexpr std::string_view kDescription  =
        "TCP in any state other than CLOSED, SYN-SENT and LISTEN MUST "
        "ignore a RST segment with OTW SEQ number (RFC 793 §3.9 p69 "
        "Event Processing). 8 spec iterations exercise wst ∈ "
        "{SYN-RCVD, EST, FW1, FW2, CW, CLOSING, LA, TW}";

    // Migrated onto the Tier-2 DUT-control seam: phase 1 puts the DUT
    // into LISTEN via the listen-only seam verb (driveSeamListen);
    // phases 2..8 active-OPEN via driveSeamActiveOpen and drive the DUT
    // CLOSE through the seam (closeTcp / driveSeamCloseToClosing /
    // driveSeamTimeWaitFw2), so the case runs unchanged on whichever
    // backend --dut-control selected. The tester-side raw OTW-RST
    // inject, AckDrop / RstDrop, shutdown(WR), and silent dispose stay
    // case-owned. The deferred-phase lambdas capture an IDutControl*
    // (CLI-owned, outlives the scheduler callbacks) as in
    // FLAGS_PROCESSING_09.
    //
    // Each phase drives DUT to its target state, then raw-injects a
    // RST with seq = snd_nxt + kOutOfWindowSeqOffset (16 MB past
    // tester's expected seq, well outside Linux's plausible
    // window-scale ceiling). The 3 s absence window per phase
    // observes whether DUT emits any RST or pure ACK on the
    // 4-tuple — both are wire-observable spec violations. The narrow
    // guard tolerates DUT FIN+ACK retransmits in states where tester
    // AckDrop pins DUT (FW1 / LA) without false-firing.
    //
    // Phase port-quad map (phase 1 passive, 2..8 active):
    //   1 SYN-RCVD: (kBasicsListenPort, kBasicsTesterPort)
    //   2 EST:      (kBasicsActiveLocalPort + 0, kBasicsActiveRemotePort + 0)
    //   3 FW1:      (kBasicsActiveLocalPort + 1, kBasicsActiveRemotePort + 1)
    //   4 FW2:      (kBasicsActiveLocalPort + 2, kBasicsActiveRemotePort + 2)
    //   5 CW:       (kBasicsActiveLocalPort + 3, kBasicsActiveRemotePort + 3)
    //   6 CLOSING:  (kBasicsActiveLocalPort + 4, kBasicsActiveRemotePort + 4)
    //   7 LA:       (kBasicsActiveLocalPort + 5, kBasicsActiveRemotePort + 5)
    //   8 TW:       (kBasicsActiveLocalPort + 6, kBasicsActiveRemotePort + 6)
    //
    // Phase 1 fires synchronously before kickStimulus returns (its
    // first observation state is SCXML's initial state). Phases 2..8
    // schedule via `scheduleAfterStateEntry` so each phase's
    // stimulus only runs when SCXML lands in the corresponding
    // listening_pN_handshake_ack state — required because the prior
    // phase's 3 s absence is wall-clock; a synchronous all-phases-up-
    // front stimulus would queue all events into pcap before SCXML
    // reaches state pN, then SCXML would walk the prior absence and
    // find the queue empty.
    //
    // TesterAutoRstDrop covers phase 1's stimulus body (SYN-RCVD
    // passive listen — DUT SYN+ACK lands on the unbound tester port,
    // eliciting tester-kernel auto-RST that would race-kill the
    // request_sock before our OTW RST inject). RstDrop dtor at
    // stimulus end is benign: phase 1 absence guard tolerates DUT
    // SYN+ACK retransmits (SYN flag set; not pure ACK / RST).
    //
    // TesterAutoAckDrop scopes inside phase 3 (FW1) and phase 7 (LA)
    // lambdas — function-scoped is incompatible with phase 4 (FW2
    // depends on tester-kernel auto-ACK to advance DUT past FW1) and
    // phase 8 (driveSeamTimeWaitFw2 depends on tester-kernel
    // auto-ACK during prelude). Phase 6 (CLOSING) installs its own
    // AckDrop because driveSeamCloseToClosing requires caller scope.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        {
            TesterAutoRstDrop rst_drop(cfg);
            (void)rst_drop;
            runPhase1SynRecv(cfg, iface, dut);
        }

        ::tc8::TestConfig cfg_copy = cfg;
        std::string       iface_str(iface);
        ::tc8::sce::IDutControl* dut_ptr = &dut;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase2Established(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase3FinWait1(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p4_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase4FinWait2(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p5_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase5CloseWait(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p6_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase6Closing(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p7_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase7LastAck(cfg_copy, iface_str, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p8_handshake_ack),
            [cfg_copy, iface_str, dut_ptr]() {
                runPhase8TimeWait(cfg_copy, iface_str, *dut_ptr);
            });
    }

private:
    static void emitOtwRst(const ::tc8::TestConfig& cfg,
                           std::string_view iface,
                           std::uint16_t src_port,
                           std::uint16_t dst_port,
                           std::uint32_t seq_base,
                           std::uint32_t ack_value) {
        ::tc8::stimulus::TcpSegmentSpec rst{};
        rst.src_port = src_port;
        rst.dst_port = dst_port;
        rst.seq_num  = seq_base + ::tc8::sce::tcp::kOutOfWindowSeqOffset;
        rst.ack_num  = ack_value;
        rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
        ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                                      /*initial_wait=*/std::chrono::milliseconds(0));
    }

    static void runPhase1SynRecv(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t listen_port = kBasicsListenPort;
        const std::uint16_t tester_port = kBasicsTesterPort;

        // Listen-only seam open: LISTEN on listen_port. No accept
        // completes (the OTW RST probes a SYN-RCVD request_sock that
        // never reaches the accept queue), so there is no handle to
        // close — the listen socket is reclaimed at END_TEST.
        if (!driveSeamListen(dut, listen_port)) return;

        auto snippet = TcpFrameSnippet::forDutSynAck(cfg, iface, tester_port);

        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = tester_port;
        syn.dst_port = listen_port;
        syn.seq_num  = kTesterInitialSeq;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn);

        const auto synack = snippet.tryCapture(std::chrono::milliseconds(500));
        if (synack.has_value()) {
            emitOtwRst(cfg, iface, tester_port, listen_port,
                       /*seq_base=*/kTesterInitialSeq + 1U,
                       /*ack_value=*/synack->seq_num + 1U);
        }
    }

    static void runPhase2Established(const ::tc8::TestConfig& cfg,
                                     std::string_view iface,
                                     ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 0U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 0U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitOtwRst(cfg, iface, remote_port, local_port,
                       seq_range->snd_nxt, seq_range->rcv_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase3FinWait1(const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 1U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 1U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        // DUT CLOSE -> DUT FIN; tester AckDrop holds it unacked so the
        // DUT stays in FIN-WAIT-1 across the OTW-RST probe.
        dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitOtwRst(cfg, iface, remote_port, local_port,
                       seq_range->snd_nxt, seq_range->rcv_nxt - 1U);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase4FinWait2(const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 2U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 2U;

        // DUT CLOSE -> DUT FIN; with no AckDrop here the tester kernel
        // auto-ACK advances the DUT FIN-WAIT-1 -> FIN-WAIT-2. The
        // 200 ms settle lets that ACK land before the OTW-RST probe.
        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (tester_fd < 0) return;
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitOtwRst(cfg, iface, remote_port, local_port,
                       seq_range->snd_nxt, seq_range->rcv_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase5CloseWait(const ::tc8::TestConfig& cfg,
                                   std::string_view iface,
                                   ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 3U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 3U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitOtwRst(cfg, iface, remote_port, local_port,
                       seq_range->snd_nxt, seq_range->rcv_nxt);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase6Closing(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 4U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 4U;

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
            emitOtwRst(cfg, iface, remote_port, local_port,
                       info.tester_seq_post_fin,
                       info.tester_ack_post_fin - 1U);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase7LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 5U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 5U;

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
            emitOtwRst(cfg, iface, remote_port, local_port,
                       seq_range->snd_nxt, seq_range->rcv_nxt - 1U);
        }
        silentlyCloseTesterFd(tester_fd);
    }

    static void runPhase8TimeWait(const ::tc8::TestConfig& cfg,
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 6U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 6U;

        const auto info = driveSeamTimeWaitFw2(
            dut, cfg, local_port, remote_port);
        if (info.ok) {
            emitOtwRst(cfg, iface, remote_port, local_port,
                       info.tester_seq_post_fin,
                       info.tester_ack_post_fin);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid15SM, tcp_flags_invalid_15)
