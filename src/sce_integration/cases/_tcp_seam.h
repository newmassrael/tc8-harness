#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_config.h"

namespace tc8::sce::tcp {

// Core TCP DUT-control seam helpers: the backend-agnostic vocabulary cases use
// to drive the DUT's connection + data plane through the `ITcpControl` seam
// instead of the opcode Upper Tester directly — active OPEN
// (driveSeamActiveOpen, the Tier-2 counterpart of driveActiveOpenEstablished),
// embryonic SYN-SENT open (driveSeamSynSentOpen), connect (seamConnectTcp), and
// the DUT-send verbs (seamSendTcp / seamSendTcpPattern). The passive-OPEN and
// TIME-WAIT-prelude helpers extend this base in sibling headers
// (_tcp_seam_passive_open.h, _tcp_seam_time_wait_prelude.h). A case built on
// these runs unchanged on whichever backend `--dut-control` selected (opcode UT
// or AUTOSAR testability) — the Tier-2 North Star
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

// Shared seam active connect (the single source of truth for both the
// established active-OPEN and the SYN-SENT helpers): bind the DUT's local
// endpoint (do_bind + local_port) and connect to the tester `remote_port` — the
// standard CREATE_AND_BIND + CONNECT. `phase` labels the caller's intent for the
// ops-diagnostic failure log. Returns the DUT's connected socket, or nullopt.
//
// Active-OPEN cases require the DUT's TCP data plane (kCapTcpControl). Both
// shipped backends expose it; a future backend that does not must be
// conditioning-skipped by the centralised capability gate (Tier 2 2b#4) BEFORE
// stimulus runs — a silent return here would mis-report as a timeout FAIL, not a
// SKIP. The deref is therefore contract-guaranteed; the assert documents it.
//
// connectTcp returns nullopt only on failure (RPC timeout, bind collision, a
// refused connect); the stderr line names the backend so a dual-backend smoke
// run points at the right side and a failed open does not mis-report downstream
// as a DUT "no SYN / no FIN" timeout. Matches the fprintf-on-failure convention
// of the other tcp-pilot tester helpers (TesterTcpListener, connectToDutTcp).
inline std::optional<::tc8::sce::DutConnection> seamConnectTcp(
    ::tc8::sce::IDutControl &dut, const ::tc8::TestConfig &cfg,
    std::uint16_t local_port, std::uint16_t remote_port, const char *phase) {
    auto conn = ::tc8::sce::seamTcpControl(dut).connectTcp(
        ::tc8::sce::Endpoint{cfg.ipv4.tester_ip, remote_port},
        ::tc8::sce::BindSpec{/*do_bind=*/true, local_port, /*local_addr_be=*/0});
    if (!conn) {
        std::fprintf(stderr,
                     "tcp-pilot: seam %s failed (connectTcp local=%u "
                     "remote=%u, backend=%s)\n",
                     phase, local_port, remote_port, dut.backendName());
    }
    return conn;
}

// Thin convenience over `ITcpControl::sendTcp` for the common DUT-send case:
// transmit a fixed-size byte array verbatim (a literal send). Collapses the
// array -> vector idiom every DUT-send case otherwise repeats (HEADER_01,
// CHECKSUM_03, ACKNOWLEDGEMENT_02/04, NAGLE_02/03, FLAGS_PROCESSING_10,
// PROBING_WINDOWS_02/04/05/06, RETRANSMISSION_TO_03/04/08).
//
// The tcpControl() deref is contract-guaranteed: a DUT-send case has already
// driven an active OPEN through the seam (kCapTcpControl), and a backend lacking
// it is conditioning-skipped by the centralised capability gate before stimulus
// runs. The assert documents that invariant.
template <std::size_t N>
inline bool seamSendTcp(::tc8::sce::IDutControl &dut, ::tc8::sce::DutSocket sock,
                        const std::array<std::uint8_t, N> &payload) {
    return ::tc8::sce::seamTcpControl(dut).sendTcp(
        sock, std::vector<std::uint8_t>(payload.begin(), payload.end()));
}

// Bulk / pattern DUT send: make the DUT emit `total_len` bytes formed by
// repeating a single `pattern` byte (ITcpControl::sendTcpPattern). The bulk
// generation lives DUT-side so the request stays compact and bypasses the
// opcode UT's literal-payload cap (kMaxPayload, 256 B). Cases use this for the
// MSS / segmentation / window-shrink flows that need the DUT's send buffer to
// overflow its negotiated MSS so the stack segments the payload (NAGLE_03,
// PROBING_WINDOWS_03, MSS_OPTIONS_09).
//
// The tcpControl() deref is contract-guaranteed exactly as in seamSendTcp: a
// DUT-send case has already driven an OPEN through the seam (kCapTcpControl),
// and a backend lacking it is conditioning-skipped by the centralised
// capability gate before stimulus runs. The assert documents that invariant.
inline bool seamSendTcpPattern(::tc8::sce::IDutControl &dut, ::tc8::sce::DutSocket sock,
                               std::uint8_t pattern, std::uint16_t total_len) {
    return ::tc8::sce::seamTcpControl(dut).sendTcpPattern(sock, pattern, total_len);
}

inline SeamActiveOpen driveSeamActiveOpen(::tc8::sce::IDutControl &dut,
                                          const ::tc8::TestConfig &cfg,
                                          std::uint16_t local_port,
                                          std::uint16_t remote_port) {
    // Listener bound before the connect; grace settles the handshake — see the
    // block comment above for the rationale of both.
    TesterTcpListener listener(remote_port);
    auto conn = seamConnectTcp(dut, cfg, local_port, remote_port, "active-OPEN");
    std::this_thread::sleep_for(kTcpActiveHandshakeGrace);
    return SeamActiveOpen{std::move(listener), std::move(conn)};
}

// SYN-SENT counterpart of `driveSeamActiveOpen`: a seam active OPEN to a
// destination with NO tester listener, so the SYN goes unanswered and the
// DUT stays in SYN-SENT and retransmits. `connectTcp` returns the socket
// handle as soon as it is bound (still SYN-SENT), so it is immediately
// queryable via the state probe. Used by the SYN-RTO RETRANSMISSION_TO
// cases (_05/_06/_09).
//
// Unlike `driveSeamActiveOpen` there is no tester listener and no handshake
// grace: these cases observe the embryonic SYN-SENT socket, not an
// established connection. The caller owns the tester-side auto-RST
// suppression (TesterAutoRstDrop) because its lifetime differs per case
// (a deferred scheduler hold for early-breaking poll loops vs a body-scoped
// RAII for a budget-bounded loop).
//
// Returns nullopt on connectTcp failure, logging the backend + 4-tuple to
// match `driveSeamActiveOpen`'s ops-diagnostic convention so a SYN-SENT
// open failure (RPC timeout, a mis-pointed dut_iface_ip) is not
// mis-reported downstream as a DUT "no SYN" timeout.
inline std::optional<::tc8::sce::DutConnection> driveSeamSynSentOpen(
    ::tc8::sce::IDutControl &dut, const ::tc8::TestConfig &cfg,
    std::uint16_t local_port, std::uint16_t remote_port) {
    return seamConnectTcp(dut, cfg, local_port, remote_port, "SYN-SENT open");
}

}  // namespace tc8::sce::tcp
