#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
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

    // Migrated onto the Tier-2 DUT-control seam: phase 1 puts the DUT
    // into LISTEN via the listen-only seam verb (driveSeamListen) and
    // verdicts on its wire response to a tester SYN that the spec RST
    // then kills (SYN-RCVD never completes an accept, so there is no
    // handle to close). Phases 2..5 active-OPEN through
    // driveSeamActiveOpen and drive the DUT CLOSE via closeTcp, so the
    // case runs unchanged on whichever backend --dut-control selected.
    // The tester-side raw RST / verify-ACK injects, AckDrop / RstDrop,
    // and silent dispose stay case-owned. The deferred-phase lambdas
    // capture an IDutControl* (CLI-owned, outlives the scheduler
    // callbacks) as in FLAGS_PROCESSING_09.
    //
    // Phase 1 SYN-RCVD prelude is the SCXML's initial state, so its
    // stimulus runs synchronously in the body. Phases 2..5 schedule via
    // scheduleAfterStateEntry on each phase's handshake_ack state: each
    // prior phase's verify-probe absence is wall-clock, so a synchronous
    // all-phases-up-front stimulus would queue every event into pcap
    // before SCXML reaches the later state and the prior absence would
    // drain them.
    //
    // Per-phase state drive:
    //   * Phase 2 EST: active OPEN, no DUT close.
    //   * Phase 3 FW1: TesterAutoAckDrop holds the DUT FIN unacked so
    //     the DUT stays in FIN-WAIT-1 across the verify probe.
    //   * Phase 4 FW2: no AckDrop — the tester kernel auto-ACK advances
    //     the DUT FIN-WAIT-1 -> FIN-WAIT-2; no shutdown(WR) follows.
    //   * Phase 5 CW: tester shutdown(WR) -> DUT CLOSE-WAIT, no DUT close.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1SynRecv(cfg, iface, dut);

        std::string       iface_copy(iface);
        ::tc8::TestConfig cfg_copy = cfg;
        ::tc8::sce::IDutControl* dut_ptr = &dut;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase2Established(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase3FinWait1(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p4_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase4FinWait2(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p5_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase5CloseWait(cfg_copy, iface_copy, *dut_ptr);
            });
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
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        constexpr std::uint16_t kListenPort = kBasicsListenPort + 12U;
        constexpr std::uint16_t kTesterPort = kBasicsTesterPort + 76U;

        // Listen-only seam open: LISTEN on kListenPort. No accept
        // completes (the spec RST kills the SYN-RCVD request), so there
        // is no handle to close — the listen socket is reclaimed at
        // END_TEST.
        if (!driveSeamListen(dut, kListenPort)) return;

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
                                     std::string_view iface,
                                     ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 60U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 60U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
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
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 61U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 61U;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        // DUT CLOSE -> DUT FIN; the tester AckDrop holds it unacked so
        // the DUT stays in FIN-WAIT-1 across the verify probe.
        dut.tcpControl()->closeTcp(open.conn->socket);
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
                                  std::string_view iface,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 62U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 62U;

        // Drive DUT to FW2: the DUT CLOSE emits the DUT FIN, and the
        // tester kernel's auto-ACK (no AckDrop here, unlike the FW1
        // phase) advances the DUT FIN-WAIT-1 -> FIN-WAIT-2. No
        // shutdown(WR) follows, so the DUT stops at FW2 rather than
        // proceeding to TIME-WAIT. The 200 ms settle lets that ACK land
        // before the verify probe.
        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        dut.tcpControl()->closeTcp(open.conn->socket);
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
                                   std::string_view iface,
                                   ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 63U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 63U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
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
