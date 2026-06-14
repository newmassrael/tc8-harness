#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_closing_09_sm.h"

namespace tc8::sce::cases {

using TcpClosing09SM = ::SCE::Generated::tcp_closing_09::tcp_closing_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpClosing09SM>
    : TcpAnyBase<cases::TcpClosing09SM> {
    static constexpr std::string_view kCaseId       = "TCP_CLOSING_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.8";
    static constexpr std::string_view kDescription  =
        "TCP in ESTABLISHED state MUST enter CLOSE-WAIT on receiving "
        "FIN; the application MAY send remaining data and TCP MUST "
        "stay in CLOSE-WAIT until app close (RFC 793 §3.5 p38 "
        "Closing a Connection)";

    // 16-byte payload pattern matched verbatim by SCXML's
    // listening_dut_data guard (`payload_len == 16U`). Pattern bytes
    // 0x5A distinct from the §4.8.6.8 _03 RST payload (0xA5) so a pcap
    // reader can attribute a stray data segment to the correct case.
    static constexpr std::size_t kPayloadLen = 16U;

    // Single iteration, backend-agnostic (opcode UT or AUTOSAR
    // testability). Seam active-OPEN handshake on +72 quad → tester
    // shutdown(SHUT_WR) emits FIN+ACK from kernel → DUT enters
    // CLOSE-WAIT and pure-ACKs the FIN → the seam DUT-send drives the
    // DUT app's send() of kPayloadLen bytes → DUT emits PSH+ACK with
    // payload → 3 s remain-in-CW absence asserts no DUT FIN/RST →
    // silentlyCloseTesterFd disposes tester socket without emitting
    // FIN/RST so the absence window stays clean.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kPortOffset = 72U;
        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kPortOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kPortOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        if (!open.conn) return;

        // Tester FIN: kernel emits FIN+ACK on shutdown(WR). DUT in
        // EST processes the FIN, emits pure ACK, transitions to
        // CLOSE-WAIT.
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));

        // Seam DUT-send → DUT app send() → DUT emits PSH+ACK with
        // payload bytes.
        std::vector<std::uint8_t> payload(kPayloadLen, 0x5AU);
        seamTcpControl(dut).sendTcp(open.conn->socket, payload);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Silent tester disposal — TCP_REPAIR + close drops the
        // socket without emitting tester FIN or RST, so the
        // remain-in-CW absence window observes spec-conformant DUT
        // silence (no spurious tester-side stimulus to drive DUT
        // out of CW).
        silentlyCloseTesterFd(tester_fd);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack";
            case State::Fail_no_dut_fin_ack:        return "fail:no_dut_ack_to_tester_fin_in_est";
            case State::Fail_no_dut_data:           return "fail:no_dut_data_segment_in_close_wait";
            case State::Fail_dut_left_cw:           return "fail:dut_emitted_fin_or_rst_in_close_wait";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpClosing09SM, tcp_closing_09)
