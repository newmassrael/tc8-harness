#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_09_sm.h"

namespace tc8::sce::cases {

using TcpBasics09SM = ::SCE::Generated::tcp_basics_09::tcp_basics_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics09SM>
    : TcpAnyBase<cases::TcpBasics09SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_09";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST move to CLOSED state after receiving an ACK of the "
        "sent FIN in LAST-ACK state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:654):
    //   1. TESTER: Cause DUT LAST-ACK — passive close path.
    //   2. DUT:    Send FIN entering LAST-ACK.
    //   3. TESTER: Send ACK for DUT's FIN — tester kernel auto-ACK.
    //   4. TESTER: Send a non-RST segment to the closed port.
    //   5. DUT:    Send a RST — verifies CLOSED.
    //
    // Stimulus stages (each separated by a brief grace so the kernel
    // FSMs settle into the expected per-stage state before the next
    // edge fires):
    //   a. Active-OPEN handshake — DUT in ESTABLISHED.
    //   b. Tester FIN (shutdown SHUT_WR on accepted fd) — DUT auto-ACK
    //      the FIN, enters CLOSE-WAIT.
    //   c. UT close — DUT close path emits its own FIN, enters
    //      LAST-ACK. SCXML observes this FIN as the spec step-2
    //      assertion.
    //   d. Wait for the tester kernel's auto-ACK of the DUT's FIN to
    //      land at the DUT — the LAST-ACK → CLOSED transition trigger.
    //   e. Raw-inject a SYN-only stimulus to the (now-closed) DUT port,
    //      mirroring the BASICS_04 closed-port flavour. DUT responds
    //      with a RST — the spec step-5 assertion.
    //
    // The non-RST stimulus is a SYN (kTcpFlagSyn) — the same flavour
    // BASICS_04 iter 1 uses; "non-RST segment" leaves the choice open
    // and SYN provides the cleanest closed-port → RST path with no
    // payload to sequence.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto listener = driveActiveOpenEstablished(
            cfg, iface, cfg.dut.mac,
            /*open_req_id=*/1,
            kBasicsActiveLocalPort  + kTcpBasics09LocalOffset,
            kBasicsActiveRemotePort + kTcpBasics09LocalOffset);

        // Stage b: tester FIN puts DUT in CLOSE-WAIT.
        const int tester_fd = listener.acceptOne();
        if (tester_fd >= 0) {
            ::shutdown(tester_fd, SHUT_WR);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Stage c: UT close → DUT FIN, LAST-ACK.
        sendCloseTcpSocketRequest(
            cfg, iface, cfg.dut.mac,
            /*req_id=*/2, /*socket_id=*/1);

        // Stage d: grace for tester kernel's auto-ACK of the DUT's
        // FIN to reach the DUT and clinch LAST-ACK → CLOSED. Without
        // this wait the closed-port stimulus might race ahead and
        // arrive while the DUT is still in LAST-ACK, where the
        // response semantics differ (LAST-ACK accepts only the ACK of
        // its own FIN; other segments are dropped or ACKed, not RST'd).
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (tester_fd >= 0) ::close(tester_fd);

        // Stage e: raw-inject SYN to closed port — DUT responds RST.
        // Source port pinned to kBasicsTesterPort so the SCXML's RST
        // pass guard matches a deterministic dst_port; without this
        // pin the kernel would pick an ephemeral source and the
        // reverse-direction RST's dst_port would be unknowable to the
        // SCXML at compile time.
        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsActiveLocalPort + kTcpBasics09LocalOffset,
                        /*flags=*/::tc8::stimulus::kTcpFlagSyn,
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0U);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                   return "pass";
            case State::Fail_timeout_fin:       return "fail:no_dut_fin_into_last_ack";
            case State::Fail_timeout_rst:       return "fail:no_dut_rst_from_closed";
            default:                            return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics09SM, tcp_basics_09)
