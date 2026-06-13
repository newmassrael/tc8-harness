#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <thread>
#include <utility>

#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_config.h"

namespace tc8::sce::tcp {

// Tier-2 counterpart of `driveActiveOpenEstablished` (tcp_pilot_common.h):
// the active-OPEN prelude routed through the backend-agnostic `ITcpControl`
// seam instead of the opcode Upper Tester directly. A case built on this
// helper runs unchanged on whichever backend `--dut-control` selected (opcode
// UT or AUTOSAR testability) — the Tier-2 North Star
// (claudedocs/testability_seam_tier2_design.md).
//
// Lives in its own header (not tcp_pilot_common.h) on purpose: it pulls in
// dut_control.h, and tcp_pilot_common.h is shared by ~113 TCP case TUs that
// must not take on the concrete-backend includes. Only the TCP cases migrated
// onto the seam include this file.
//
// The tester-side auxiliary listener stays case-owned: it is harness
// infrastructure (the real receiver the DUT's SYN lands on), not DUT control,
// so it is bound here on the tester side BEFORE the DUT connects. Without it
// the DUT's SYN would hit the tester kernel's closed-port path and provoke a
// RST that collapses the embryonic handshake.
//
// The DUT's active open carries an explicit local BindSpec so its source port
// is the spec-pinned `local_port` the SCXML guard filters on (standard
// CREATE_AND_BIND + CONNECT). The `kTcpActiveHandshakeGrace` settle mirrors
// `driveActiveOpenEstablished`: it gives the SYN -> SYN+ACK -> ACK round trip
// time to land in the pcap ring before the caller arms the SCXML deadline or
// issues a follow-up close.
//
// Unlike `driveActiveOpenEstablished` this helper does NOT also wait
// `kTcpUtRpcWait`. That wait exists in the opcode-direct path because its open
// is an AF_PACKET fire-and-forget inject — the tester must pause for the DUT
// to process it. `connectTcp` is instead a synchronous round trip (the backend
// has issued the active open by the time it returns), so the post-open RPC
// settle is already subsumed and only the handshake grace remains.
//
// `local_port` / `remote_port` are intentionally non-default — every caller
// must pick a unique 4-tuple from the +200.. reservation block so a
// TIME-WAIT / LAST_ACK residue from a sibling on the same worker netns does
// not collide with the next case's bind (see
// reference_active_open_port_quad_collision.md).
struct SeamActiveOpen {
    TesterTcpListener                       listener;  // tester-side receiver (RAII, move-only)
    std::optional<::tc8::sce::DutConnection> conn;     // DUT's connected socket, or nullopt
};

inline SeamActiveOpen driveSeamActiveOpen(::tc8::sce::IDutControl &dut,
                                          const ::tc8::TestConfig &cfg,
                                          std::uint16_t local_port,
                                          std::uint16_t remote_port) {
    // Active-OPEN cases require the DUT's TCP data plane (kCapTcpControl).
    // Both shipped backends expose it; a future backend that does not must be
    // conditioning-skipped by the centralised capability gate (Tier 2 2b#4)
    // BEFORE stimulus runs — a silent return here would mis-report as a
    // timeout FAIL, not a SKIP. The deref is therefore contract-guaranteed;
    // the assert documents it.
    ::tc8::sce::ITcpControl *tcp = dut.tcpControl();
    assert(tcp != nullptr && "active-OPEN cases require kCapTcpControl");

    TesterTcpListener listener(remote_port);
    auto conn = tcp->connectTcp(
        ::tc8::sce::Endpoint{cfg.ipv4.tester_ip, remote_port},
        ::tc8::sce::BindSpec{/*do_bind=*/true, local_port, /*local_addr_be=*/0});

    if (!conn) {
        // Surface the backend-side failure for ops diagnosis. connectTcp
        // returns nullopt only on failure (RPC timeout, bind collision, a
        // refused connect); without this line a failed open would mis-report
        // downstream as a DUT "no SYN / no FIN" timeout, hiding the real
        // cause. Names the backend so a dual-backend smoke run points at the
        // right side. Matches the fprintf-on-failure convention of the other
        // tcp-pilot tester helpers (TesterTcpListener, connectToDutTcp).
        std::fprintf(stderr,
                     "tcp-pilot: seam active-OPEN failed (connectTcp "
                     "local=%u remote=%u, backend=%s)\n",
                     local_port, remote_port, dut.backendName());
    }

    std::this_thread::sleep_for(kTcpActiveHandshakeGrace);
    return SeamActiveOpen{std::move(listener), std::move(conn)};
}

}  // namespace tc8::sce::tcp
