#pragma once

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <optional>

#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_config.h"

namespace tc8::sce::tcp {

// Tier-2 passive-OPEN counterpart of `driveSeamActiveOpen`
// (_tcp_seam_active_open.h): drive the DUT through a LISTEN-then-ACCEPT via the
// backend-agnostic `ITcpControl::acceptTcp` seam instead of the opcode Upper
// Tester's OpOpenTcpSocket(Passive) builder directly. A case built on this
// helper runs unchanged on whichever backend `--dut-control` selected (opcode
// UT or AUTOSAR testability) — the Tier-2 North Star
// (claudedocs/testability_seam_tier2_design.md).
//
// Lives in its own header (not tcp_pilot_common.h) for the same reason as the
// active-open helper: it pulls in dut_control.h, and tcp_pilot_common.h is
// shared by ~113 TCP case TUs that must not take on the concrete-backend
// includes. Only the passive-open cases migrated onto the seam include this
// file.
//
// `acceptTcp` orchestrates the whole passive open: it issues the DUT
// CREATE_AND_BIND + LISTEN, invokes `trigger` to drive ONE inbound tester
// connection while the DUT is listening, then confirms the DUT accepted it
// (opcode: an OpQueryTcpEstablished poll on the accepted fd; testability: the
// async LISTEN_AND_ACCEPT event). The tester connect is therefore the trigger
// body, and stays case-owned harness infrastructure — it is the real client the
// DUT's SYN+ACK completes a handshake with, not DUT control.
//
// The tester connects with `TcpPostClose::kKeepOpen` and the helper hands the
// connected fd back: the connection must stay ESTABLISHED across the backend's
// accept-confirmation. The opcode backend reads the accepted fd's live
// TCP_INFO state, so a connect that closed immediately could race the poll into
// CLOSE-WAIT and mis-report the accept as failed. The CASE owns `tester_fd`
// afterwards and drives its own teardown / FIN stimulus on it — a plain close
// for a pure SYN+ACK observation, or shutdown(SHUT_WR) to emit the FIN a
// received-in-ESTABLISHED case asserts on. Driving the FIN after the accept is
// confirmed (rather than inside the connect helper) also makes the "FIN
// received in ESTABLISHED state" precondition explicit.
//
// Returns a nullopt `conn` on accept failure, logging the backend + listen port
// to match `driveSeamActiveOpen`'s ops-diagnostic convention so a passive-open
// failure (RPC timeout, an acceptor that never saw the tester connect) is not
// mis-reported downstream as a DUT "no SYN+ACK" timeout. `tester_fd` is still
// returned (it may be valid even when the accept-confirmation failed) so the
// caller can always close it.
struct SeamPassiveOpen {
    std::optional<::tc8::sce::DutConnection> conn;          // accepted DUT connection, or nullopt
    int                                      tester_fd = -1;  // tester client fd, kept open
};

inline SeamPassiveOpen driveSeamPassiveOpen(::tc8::sce::IDutControl &dut,
                                            const ::tc8::TestConfig &cfg,
                                            std::uint16_t listen_port) {
    // Passive-OPEN cases require the DUT's TCP data plane (kCapTcpControl).
    // Both shipped backends expose it; a future backend that does not must be
    // conditioning-skipped by the centralised capability gate (Tier 2 2b#4)
    // BEFORE stimulus runs — a silent return here would mis-report as a timeout
    // FAIL, not a SKIP. The deref is therefore contract-guaranteed; the assert
    // documents it.
    ::tc8::sce::ITcpControl *tcp = dut.tcpControl();
    assert(tcp != nullptr && "passive-OPEN cases require kCapTcpControl");

    int tester_fd = -1;
    auto conn = tcp->acceptTcp(
        ::tc8::sce::BindSpec{/*do_bind=*/true, listen_port, /*local_addr_be=*/0},
        [&] { connectToDutTcp(cfg, listen_port, TcpPostClose::kKeepOpen, &tester_fd); });

    if (!conn) {
        std::fprintf(stderr,
                     "tcp-pilot: seam passive-OPEN failed (acceptTcp "
                     "listen=%u, backend=%s)\n",
                     listen_port, dut.backendName());
    }
    return SeamPassiveOpen{std::move(conn), tester_fd};
}

}  // namespace tc8::sce::tcp
