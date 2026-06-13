#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <sys/socket.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_03_sm.h"

namespace tc8::sce::cases {

using TcpBasics03SM = ::SCE::Generated::tcp_basics_03::tcp_basics_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics03SM>
    : TcpAnyBase<cases::TcpBasics03SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_03";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP MUST send an ACK in response to a FIN received in "
        "ESTABLISHED state (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:460):
    //   1. TESTER: Cause DUT ESTABLISHED — passive open + connect().
    //   2. TESTER: Send FIN,ACK — shutdown(SHUT_WR) on the client fd.
    //   3. DUT:    Send ACK      — observed on pcap.
    //
    // Migrated onto the Tier-2 DUT-control seam: the passive open runs through
    // `driveSeamPassiveOpen` (ITcpControl::acceptTcp) and the DUT teardown
    // through `closeTcp`, so the case runs unchanged on whichever backend
    // `--dut-control` selected (opcode UT or AUTOSAR testability). The tester
    // connect is the seam trigger; the FIN it then drives is case-owned harness
    // infrastructure on the tester fd the seam hands back.
    //
    // The FIN is emitted only after the seam confirms the accept, so the DUT is
    // genuinely ESTABLISHED when the FIN arrives (the precondition the spec
    // names). shutdown(SHUT_WR) leaves the read side open so the tester kernel
    // absorbs any follow-up DUT FIN,ACK without generating a RST; a plain
    // close() would drop the fd's socket state synchronously and any
    // later-arriving DUT segment would RST (benign here — the ACK is already
    // observed — but cleaner to avoid). A 100 ms wait after shutdown lets the
    // DUT kernel process the FIN and emit the ACK before teardown.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamPassiveOpen(dut, cfg, kBasicsListenPort);

        if (open.tester_fd >= 0) {
            ::shutdown(open.tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            ::close(open.tester_fd);
        }
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:          return "pass";
            case State::Fail_timeout:  return "fail:no_dut_ack_to_tester_fin_within_listen_window";
            default:                   return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics03SM, tcp_basics_03)
