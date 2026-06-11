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
        "DUT to wst, UT abort triggers tcp_disconnect, verify-probe ACK "
        "on killed 4-tuple proves CLOSED uniformly across iters";

    static constexpr std::uint16_t kPortOffsetClosing  = 91U;
    static constexpr std::uint16_t kPortOffsetLastAck  = 92U;
    static constexpr std::uint16_t kPortOffsetTimeWait = 93U;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        runPhase1Closing(cfg, iface);

        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy = cfg;

        // Phase 2 + 3 deferred: the per-phase active-OPEN, FIN
        // exchange, and abort all happen on the matching SCXML
        // observation entry so wire events arrive while listening
        // transitions are armed. Mirrors FP_02 / RECEIVE_04 phasing.
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p2_handshake_ack),
            [iface_copy, cfg_copy]() {
                runPhase2LastAck(cfg_copy, iface_copy);
            });
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_p3_handshake_ack),
            [iface_copy, cfg_copy]() {
                runPhase3TimeWait(cfg_copy, iface_copy);
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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_p1_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase1_closing";
            case State::Fail_p1_no_close:           return "fail:dut_did_not_close_after_abort_in_closing";
            case State::Fail_p2_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase2_last_ack";
            case State::Fail_p2_no_close:           return "fail:dut_did_not_close_after_abort_in_last_ack";
            case State::Fail_p3_no_handshake_ack:   return "fail:no_dut_handshake_ack_phase3_time_wait";
            case State::Fail_p3_no_close:           return "fail:dut_did_not_close_after_abort_in_time_wait";
            default:                                return "running";
        }
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

    // Phase 1 CLOSING: driveCloseToClosing helper drives DUT through
    // FW1 → CLOSING (caller-managed AckDrop scope). UT abort then
    // emits RST via tcp_disconnect path. silentlyCloseTesterFd
    // disposes the tester fd. AckDrop dtor at scope end removes the
    // iptables rule.
    static void runPhase1Closing(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetClosing;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetClosing;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        const auto info = driveCloseToClosing(
            cfg, iface, cfg.dut.mac, tester_fd,
            /*close_req_id=*/2, /*socket_id=*/1,
            local_port, remote_port);
        if (!info.ok) return;
        // DUT now in CLOSING; tester_fd ownership transferred to
        // caller per helper contract.

        sendAbortTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/3, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }

    // Phase 2 LAST-ACK: AckDrop installed BEFORE handshake (tester
    // outbound pure ACK to DUT FIN must be suppressed). Tester
    // shutdown(WR) drives DUT EST→CW (DUT acks tester FIN). UT
    // shutdownTcpSocketWr drives DUT CW→LAST-ACK (DUT FIN egress;
    // AckDrop blocks tester auto-ACK so DUT stays in LAST-ACK). UT
    // abort emits RST via tcp_disconnect.
    static void runPhase2LastAck(const ::tc8::TestConfig& cfg,
                                 std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetLastAck;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetLastAck;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/4, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        // Tester FIN → DUT EST→CW. The ACK DUT emits in response is
        // wire-egress (not affected by tester OUTPUT chain). Tester
        // socket transitions EST→FW1 on shutdown(WR).
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // UT shutdownTcpSocketWr → DUT CW→LAST-ACK. Tester auto-ACK
        // to DUT FIN is dropped by ack_drop; DUT stays in LAST-ACK.
        sendShutdownTcpSocketWrRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/5, /*socket_id=*/2);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // UT abort on a LAST-ACK socket → tcp_disconnect →
        // tcp_send_active_reset → DUT RST. Verify-probe still fires
        // for the closed-port RST as redundant proof.
        sendAbortTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/6, /*socket_id=*/2);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }

    // Phase 3 TIME-WAIT: UT shutdownTcpSocketWr → DUT FIN → tester
    // auto-ACK (NO AckDrop) drives DUT FW1→FW2. Tester shutdown(WR)
    // → tester FIN → DUT FW2→TW (DUT pure ACK egress). UT abort on
    // the TW socket: Linux's TIME-WAIT bucket may not emit RST
    // directly (the socket struct is detached into a tw_sock); the
    // verify-probe ACK is the wire-observable pass criterion.
    static void runPhase3TimeWait(const ::tc8::TestConfig& cfg,
                                  std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffsetTimeWait;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffsetTimeWait;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/7, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        // shutdown(WR) — DUT FIN. Tester kernel auto-ACK drives
        // DUT FW1→FW2. NO AckDrop here — we want the auto-ACK.
        sendShutdownTcpSocketWrRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/8, /*socket_id=*/3);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Tester FIN → DUT FW2→TIME-WAIT. DUT emits pure ACK; tester
        // sees it and transitions tester FW1 (after shutdown WR
        // earlier had transitioned EST→FW1) → CLOSED. Wait for DUT
        // ACK egress before issuing abort so the wire signature of
        // TW entry is captured before abort fires.
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // UT abort on TW socket. Linux's behaviour: setsockopt may
        // succeed but close on a TW-state fd typically just frees
        // the fd reference without emitting RST. The verify-probe
        // ACK is the load-bearing CLOSED-proof for this iter.
        sendAbortTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/9, /*socket_id=*/3);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort03SM, tcp_call_abort_03)
