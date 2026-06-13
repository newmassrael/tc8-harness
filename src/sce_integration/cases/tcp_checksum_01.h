#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_active_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_checksum_01_sm.h"

namespace tc8::sce::cases {

using TcpChecksum01SM = ::SCE::Generated::tcp_checksum_01::tcp_checksum_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpChecksum01SM>
    : TcpAnyBase<cases::TcpChecksum01SM> {
    static constexpr std::string_view kCaseId       = "TCP_CHECKSUM_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.2";
    static constexpr std::string_view kDescription  =
        "Receiver TCP MUST check the checksum and MUST acknowledge "
        "in case of no error (RFC 1122 §4.2.2.7 p86 TCP Checksum)";

    // Spec Test Procedure (v3.0 p301-p320.txt:128):
    //   1. TESTER: Cause DUT ESTABLISHED — active OPEN.
    //   2. TESTER: Send a data segment with correct checksum.
    //   3. DUT:    Send ACK.
    //
    // Migrated onto the Tier-2 DUT-control seam: the active OPEN runs
    // through `driveSeamActiveOpen` (ITcpControl) and the DUT teardown
    // through `closeTcp`, so the case runs unchanged on whichever backend
    // `--dut-control` selected (opcode UT or AUTOSAR testability). Only the
    // OPEN prelude is DUT control; the data send is tester-side and stays
    // case-owned harness infrastructure.
    //
    // The DATA send goes through the tester kernel's ::send() so the
    // emitted segment carries an RFC-correct checksum without the
    // stimulus needing to compute one. Tester accept() materialises a
    // userland fd from the auxiliary listener's queue — without it
    // there is no way to drive an application-level send and the spec
    // step "Send a data segment" cannot be issued.
    //
    // The 4 B payload is symmetric with CHECKSUM_03 — small enough to
    // fit one segment, non-empty so a delayed-ACK from DUT lands
    // promptly (Linux sends an immediate ACK for non-empty data above
    // a threshold; the threshold is far above 4 B but the data also
    // satisfies the SCXML's "ACK arrived after stimulus" expectation
    // because the listen window is 5 s and Linux's max delayed-ACK is
    // ~40 ms).
    static constexpr std::array<std::uint8_t, 4> kChecksumPayload = {
        0x12U, 0x34U, 0x56U, 0x78U};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamActiveOpen(
            dut, cfg,
            kBasicsActiveLocalPort  + kTcpChecksum01LocalOffset,
            kBasicsActiveRemotePort + kTcpChecksum01LocalOffset);

        // Acquire the tester-side connected fd so we can drive
        // ::send() at the application layer. acceptOne uses 1 s
        // timeout — under a busy worker netns the handshake completes
        // in single-digit milliseconds, the timeout is sized for
        // scheduling jitter not happy-path latency.
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd >= 0) {
            (void)::send(tester_fd, kChecksumPayload.data(),
                          kChecksumPayload.size(), MSG_NOSIGNAL);
            // Brief wait so the DUT's data-elicited ACK lands before
            // the stimulus tail closes the connection. Linux's
            // delayed-ACK upper bound is ~40 ms; 100 ms covers it
            // with margin without bloating the per-case wall-time.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ::close(tester_fd);
        }

        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                       return "pass";
            case State::Fail_no_handshake_ack:      return "fail:no_dut_handshake_ack_within_listen_window";
            case State::Fail_no_data_ack:           return "fail:no_dut_ack_to_correct_checksum_data";
            default:                                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpChecksum01SM, tcp_checksum_01)
