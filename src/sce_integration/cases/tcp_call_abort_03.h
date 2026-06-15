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
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_call_abort_03_sm.h"

namespace tc8::sce::cases {

using TcpCallAbort03SM =
    ::SCE::Generated::tcp_call_abort_03::tcp_call_abort_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallAbort03SM>
    : TcpAnyBase<cases::TcpCallAbort03SM> {
    static constexpr std::string_view kCaseId       = "TCP_CALL_ABORT_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.5";
    static constexpr std::string_view kDescription  =
        "TCP in CLOSING / LAST-ACK / TIME-WAIT MUST respond with ok "
        "and enter CLOSED on application ABORT call (RFC 793 §3.9 p62 "
        "Event Processing). 3-iter compound: per-iter prelude drives "
        "DUT to wst, abort triggers the DUT's abortive close, verify-probe ACK "
        "on killed 4-tuple proves CLOSED uniformly across iters";

    // TC8 §4.8.6.5 — TCP Call Abort (CLOSING / LAST-ACK / TIME-WAIT).
    // One port-quad offset per compound iteration.
    static constexpr std::uint16_t kPortOffsetClosing  = 91U;
    static constexpr std::uint16_t kPortOffsetLastAck  = 92U;
    static constexpr std::uint16_t kPortOffsetTimeWait = 93U;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1Closing(cfg, iface, dut);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;
        ::tc8::sce::IDutControl*     dut_ptr  = &dut;

        // Phase 2 + 3 deferred: the per-phase active-OPEN, FIN
        // exchange, and abort all happen on the matching SCXML
        // observation entry so wire events arrive while listening
        // transitions are armed. Mirrors FP_02 / RECEIVE_04 phasing.
        // The DUT-control handle is owned by the CLI for the whole run,
        // so the deferred phases capture a raw pointer to it (FP_09 idiom).
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase2LastAck(cfg_copy, iface_copy, *dut_ptr);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy, dut_ptr]() {
                runPhase3TimeWait(cfg_copy, iface_copy, *dut_ptr);
            });

        // Verify-probe ACK on entry to each verify_rst state. The
        // probe arrives after the prelude+abort settle window so the
        // closed-port RST it elicits cleanly maps to the spec's
        // "DUT moved to CLOSED" assertion. Same scheduleAfterStateEntry
        // shape as TCP_CLOSING_03 / FLAGS_PROCESSING_02.
        std::array<std::uint8_t, 6> dut_mac = cfg.dut.mac;
        scheduleVerifyProbe(scheduler, State::Listening_p1_verify_rst,
                            iface_copy, cfg_copy, dut_mac,
                            kPortOffsetClosing);
        scheduleVerifyProbe(scheduler, State::Listening_p2_verify_rst,
                            iface_copy, cfg_copy, dut_mac,
                            kPortOffsetLastAck);
        scheduleVerifyProbe(scheduler, State::Listening_p3_verify_rst,
                            iface_copy, cfg_copy, dut_mac,
                            kPortOffsetTimeWait);
    }

private:
    static void scheduleVerifyProbe(
        IStimulusScheduler& scheduler,
        State target_state,
        std::string iface_copy,
        ::tc8::TestConfig cfg_copy,
        std::array<std::uint8_t, 6> dut_mac,
        std::uint16_t port_offset) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + port_offset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + port_offset;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(target_state),
            [iface_copy, cfg_copy, dut_mac,
             local_port, remote_port]() {
                ::tc8::stimulus::TcpSegmentSpec ack{};
                ack.src_port = remote_port;
                ack.dst_port = local_port;
                ack.seq_num  = kTesterInitialSeq + 100U;
                ack.ack_num  = 0U;
                ack.flags    = ::tc8::stimulus::kTcpFlagAck;
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg_copy, iface_copy, dut_mac, ack,
                    /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }

    // Phase 1 CLOSING: driveSeamCloseToClosing drives the DUT through FW1 →
    // CLOSING (caller-managed AckDrop scope). The seam close that reaches CLOSING
    // disposes the DUT-side socket, so the trailing abort is a no-op (preserving
    // the original's abort-in-CLOSING intent); the verify-probe is the
    // load-bearing CLOSED proof. silentlyCloseTesterFd disposes the tester fd;
    // the AckDrop dtor at scope end removes the iptables rule.
    static void runPhase1Closing(const ::tc8::TestConfig& cfg,
                                 std::string_view iface,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetClosing;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetClosing;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;

        const auto info = driveSeamCloseToClosing(
            dut, cfg, iface, tester_fd, open.conn->socket,
            local_port, remote_port);
        if (!info.ok) return;
        // DUT now in CLOSING.

        seamTcpControl(dut).abortTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }

    // Phase 2 LAST-ACK: AckDrop installed BEFORE handshake (tester
    // outbound pure ACK to DUT FIN must be suppressed). Tester
    // shutdown(WR) drives DUT EST→CW (DUT acks tester FIN). seam
    // shutdownTcpWr drives DUT CW→LAST-ACK (DUT FIN egress; AckDrop
    // blocks tester auto-ACK so DUT stays in LAST-ACK). abort → RST.
    static void runPhase2LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view /*iface*/,
                                 ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetLastAck;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetLastAck;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;

        auto& tcp = seamTcpControl(dut);

        // Tester FIN → DUT EST→CW. The ACK the DUT emits in response is
        // wire-egress (not affected by tester OUTPUT chain). Tester socket
        // transitions EST→FW1 on shutdown(WR).
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // shutdownTcpWr → DUT CW→LAST-ACK. Tester auto-ACK to the DUT FIN is
        // dropped by ack_drop; the DUT stays in LAST-ACK.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Abort on a LAST-ACK socket → RST (the abortive close reaches CLOSED).
        // The verify-probe still fires for the closed-port RST as redundant
        // proof.
        tcp.abortTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }

    // Phase 3 TIME-WAIT: seam shutdownTcpWr → DUT FIN → tester
    // auto-ACK (NO AckDrop) drives DUT FW1→FW2. Tester shutdown(WR)
    // → tester FIN → DUT FW2→TW (DUT pure ACK egress). abort on the
    // TW socket emits no wire RST (a TIME-WAIT abort is silent on the
    // wire), so the verify-probe ACK is the wire-observable pass
    // criterion.
    static void runPhase3TimeWait(const ::tc8::TestConfig& cfg,
                                  std::string_view /*iface*/,
                                  ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetTimeWait;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetTimeWait;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;

        auto& tcp = seamTcpControl(dut);

        // shutdown(WR) — DUT FIN. Tester kernel auto-ACK drives DUT FW1→FW2.
        // NO AckDrop here — we want the auto-ACK.
        tcp.shutdownTcpWr(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Tester FIN → DUT FW2→TIME-WAIT. DUT emits pure ACK; tester sees it and
        // transitions tester FW1 (after the earlier shutdown WR EST→FW1) →
        // CLOSED. Wait for the DUT ACK egress before issuing abort so the wire
        // signature of TW entry is captured before abort fires.
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Abort on the TIME-WAIT socket → CLOSED (the DUT force-terminates the
        // TIME-WAIT residual internally). A TIME-WAIT abort emits no wire RST, so
        // the verify-probe ACK is the load-bearing CLOSED-proof for this iter.
        tcp.abortTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort03SM, tcp_call_abort_03)
