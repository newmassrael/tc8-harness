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

#include "tcp_connection_estab_07_sm.h"

namespace tc8::sce::cases {

using TcpConnectionEstab07SM =
    ::SCE::Generated::tcp_connection_estab_07::tcp_connection_estab_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpConnectionEstab07SM>
    : TcpAnyBase<cases::TcpConnectionEstab07SM> {
    static constexpr std::string_view kCaseId       = "TCP_CONNECTION_ESTAB_07";
    static constexpr std::string_view kSpecSection  = "4.8.6.15";
    static constexpr std::string_view kDescription  =
        "DUT acks tester FIN and on user Close emits its own FIN to "
        "reach CLOSED (RFC 793 §3.5 Closing a Connection).";

    // Migrated onto the Tier-2 DUT-control seam: the passive open runs through
    // `driveSeamPassiveOpen` (ITcpControl::acceptTcp) and the DUT teardown
    // through `closeTcp`, so the case runs unchanged on whichever backend
    // `--dut-control` selected (opcode UT or AUTOSAR testability). The tester
    // connect is the seam trigger; the FIN it then drives and the case-owned fd
    // teardown are harness infrastructure on the tester fd the seam hands back.
    //
    // The seam trigger keeps the connection open (kKeepOpen) so the accept is
    // confirmed before the FIN, making the "FIN received in ESTABLISHED state"
    // precondition explicit. shutdown(SHUT_WR) leaves the read side open so the
    // tester kernel absorbs the DUT's phase-2 FIN,ACK without a RST; the fd is
    // closed only after both phases complete.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        auto open = driveSeamPassiveOpen(dut, cfg, kTcpConnEstab07ListenPort);

        // Phase 1: tester FIN (write side only) → DUT auto-ACK observed by SCXML.
        if (open.tester_fd >= 0) ::shutdown(open.tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Phase 2: user Close → DUT close() → DUT FIN observed.
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        if (open.tester_fd >= 0) ::close(open.tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpConnectionEstab07SM, tcp_connection_estab_07)
