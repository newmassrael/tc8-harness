#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_call_abort_02_sm.h"

namespace tc8::sce::cases {

using TcpCallAbort02SM =
    ::SCE::Generated::tcp_call_abort_02::tcp_call_abort_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpCallAbort02SM>
    : TcpAnyBase<cases::TcpCallAbort02SM> {
    static constexpr std::string_view kCaseId       = "TCP_CALL_ABORT_02";
    static constexpr std::string_view kSpecSection  = "4.8.6.5";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST enter CLOSED on application "
        "ABORT call (RFC 793 §3.9 p62 Event Processing). UT abort "
        "(SO_LINGER {1,0} + close) drives DUT RST egress; verify-probe "
        "ACK on killed 4-tuple draws closed-port RST as wire-observable "
        "proof of CLOSED";

    // Single iteration. Active-OPEN handshake on +90 quad → UT abort
    // → DUT RST → verify-probe ACK on entry to listening_verify_rst →
    // DUT closed-port RST → pass. Same shape as TCP_CLOSING_03 modulo
    // the spec inject vs UT abort split: _03 raw-injects RST at DUT,
    // ABORT_02 drives DUT to emit its own RST via the LINGER primitive.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 90U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1, local_port, remote_port);
        const int tester_fd = listener.acceptOne();
        if (tester_fd < 0) return;

        // UT abort — tc8-dut applies SO_LINGER {1,0} + ::close →
        // kernel RST egress + immediate socket disposal. The
        // socket_id is erased from tcp_listeners_ inside the server
        // path; no further UT calls on socket_id=1 are issued.
        sendAbortTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Dispose tester fd silently — the DUT RST has already
        // killed the tester-side socket (tcp_reset → CLOSED), but
        // a stray tester FIN+ACK from a graceful close would
        // confound the verify-probe phase. TCP_REPAIR + close
        // releases the kernel state without wire egress.
        silentlyCloseTesterFd(tester_fd);

        // Verify probe: pure ACK raw-injected on the killed 4-tuple
        // after entry to listening_verify_rst. DUT-side socket is
        // gone, Linux's tcp_v4_send_reset emits a closed-port RST
        // back. Same scheduleAfterStateEntry shape as TCP_CLOSING_03
        // / FLAGS_PROCESSING_02 — phasing is wired to the SCXML
        // observation state, not wall clock.
        std::string                 iface_copy(iface);
        ::tc8::TestConfig           cfg_copy   = cfg;
        std::array<std::uint8_t, 6> dut_mac    = cfg.dut.mac;

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_verify_rst),
            [iface_copy, cfg_copy, dut_mac,
             local_port, remote_port]() {
                ::tc8::stimulus::TcpSegmentSpec ack{};
                ack.src_port = remote_port;
                ack.dst_port = local_port;
                // Arbitrary in/out-of-window seq/ack — Linux's
                // closed-port reset path emits RST(seq=incoming.ack)
                // regardless of the probe's chosen values.
                ack.seq_num  = kTesterInitialSeq + 100U;
                ack.ack_num  = 0U;
                ack.flags    = ::tc8::stimulus::kTcpFlagAck;
                ::tc8::sce::tcp::emitTcpFrame(
                    cfg_copy, iface_copy, dut_mac, ack,
                    /*initial_wait=*/std::chrono::milliseconds(0));
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_rst:            return "fail:dut_did_not_emit_rst_after_abort_in_est";
            case State::Fail_no_verify_rst:         return "fail:dut_did_not_close_after_abort_in_est";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpCallAbort02SM, tcp_call_abort_02)
