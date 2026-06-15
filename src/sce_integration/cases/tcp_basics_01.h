#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_01_sm.h"

namespace tc8::sce::cases {

using TcpBasics01SM = ::SCE::Generated::tcp_basics_01::tcp_basics_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics01SM>
    : TcpAnyBase<cases::TcpBasics01SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "TCP in LISTEN state MUST send a SYN,ACK in response to a "
        "received SYN (RFC 793 §3.2 p23 Terminology)";

    // Spec Test Procedure (v3.0 p281-p300.txt:399):
    //   1. TESTER: Cause DUT to LISTEN — a passive open on the well-known
    //      port (kBasicsListenPort = 12345).
    //   2. TESTER: Send a SYN — a kernel connect() from the tester netns. The
    //      handshake completes end-to-end because no tester-side RST is
    //      injected on the listening socket.
    //   3. DUT: Send SYN,ACK — observed on pcap; the SCXML gates on the
    //      SYN+ACK flags with src_ip == DUT.
    //
    // Migrated onto the Tier-2 DUT-control seam: the passive open runs through
    // `driveSeamPassiveOpen` (ITcpControl::acceptTcp) and the DUT teardown
    // through `closeTcp`, so the case runs unchanged on whichever backend
    // `--dut-control` selected (opcode UT or AUTOSAR testability). The DUT emits
    // SYN,ACK during the seam's accept handshake — the verdict's observable —
    // and the tester connect is the seam trigger (case-owned harness
    // infrastructure). The tester-held fd is closed after the observation so the
    // connection does not linger; the DUT socket is freed via the seam so the
    // next case on the same worker starts clean.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamPassiveOpen(dut, cfg, kBasicsListenPort);

        if (open.tester_fd >= 0) ::close(open.tester_fd);
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics01SM, tcp_basics_01)
