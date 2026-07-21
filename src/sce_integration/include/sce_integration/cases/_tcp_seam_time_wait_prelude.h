#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/cases/_tcp_seam.h"  // driveSeamActiveOpen
#include "sce_integration/dut_control.h"                  // IDutControl, DutSocket
#include "sce_integration/tcp_pilot_common.h"             // TcpTimeWaitInfo + cores
#include "sce_integration/test_config.h"

namespace tc8::sce::tcp {

// Tier-2 seam wrappers for the TIME-WAIT preludes. They bind the DUT-control
// seam's `closeTcp` to the backend-agnostic choreography cores in
// tcp_pilot_common.h (`finishFw2ToTimeWait` / `driveToTimeWaitViaClosing`) — the
// SAME cores the opcode wrappers use, so there is one source of truth for the
// wire mechanics and only the DUT-close verb differs by backend. A case built on
// these runs unchanged on whichever backend `--dut-control` selected — the
// Tier-2 North Star (claudedocs/testability_seam_tier2_design.md).
//
// Lives in its own header (not tcp_pilot_common.h, which ~113 TCP TUs share and
// must not take on dut_control.h): only the DUT-close binding needs the seam,
// so only that thin layer carries the concrete-backend include.

// FIN-WAIT-2 path: self-contained seam active OPEN, then the shared
// `finishFw2ToTimeWait` core with the DUT CLOSE bound to `closeTcp`.
inline TcpTimeWaitInfo driveSeamTimeWaitFw2(::tc8::sce::IDutControl &dut,
                                            const ::tc8::TestConfig &cfg,
                                            std::uint16_t local_port,
                                            std::uint16_t remote_port) {
    auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
    const int tester_fd = open.listener.acceptOne();
    return finishFw2ToTimeWait(tester_fd, [&]() {
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
    });
}

// CLOSING path: the caller has already established the connection through the
// seam and owns `tester_fd` (the accepted tester socket) and `dut_socket` (the
// DUT's connected socket, from the seam open's DutConnection). Delegates to the
// shared `driveToTimeWaitViaClosing` core with the DUT CLOSE bound to
// `closeTcp`; the tester-side raw inject + TCP_REPAIR dispose live in the core.
inline TcpTimeWaitInfo driveSeamCloseToTimeWaitClosing(::tc8::sce::IDutControl &dut,
                                                       const ::tc8::TestConfig &cfg,
                                                       std::string_view iface,
                                                       int tester_fd,
                                                       ::tc8::sce::DutSocket dut_socket,
                                                       std::uint16_t local_port,
                                                       std::uint16_t remote_port) {
    return driveToTimeWaitViaClosing(cfg, iface, cfg.dut.mac, tester_fd,
                                     local_port, remote_port,
                                     [&]() { dut.tcpControl()->closeTcp(dut_socket); });
}

// CLOSING path that STOPS at CLOSING (no advance to TIME-WAIT): the caller has
// already established the connection through the seam and owns `tester_fd` (the
// accepted tester socket) and `dut_socket` (the DUT's connected socket, from the
// seam open's DutConnection). Delegates to the shared `driveToClosingState` core
// with the DUT CLOSE bound to `closeTcp`. Per that core's contract the caller
// installs TesterAutoAckDrop in its own scope and silentlyCloseTesterFd's the
// (still-live) tester_fd after its post-CLOSING probe phase.
inline TcpTimeWaitInfo driveSeamCloseToClosing(::tc8::sce::IDutControl &dut,
                                               const ::tc8::TestConfig &cfg,
                                               std::string_view iface,
                                               int tester_fd,
                                               ::tc8::sce::DutSocket dut_socket,
                                               std::uint16_t local_port,
                                               std::uint16_t remote_port) {
    return driveToClosingState(cfg, iface, cfg.dut.mac, tester_fd,
                               local_port, remote_port,
                               [&]() { dut.tcpControl()->closeTcp(dut_socket); });
}

}  // namespace tc8::sce::tcp
