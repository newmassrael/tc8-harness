#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_pilot_common.h"
#include "sce_integration/test_config.h"

namespace tc8::sce::tcp {

// Tier-2 passive-OPEN counterpart of `driveSeamActiveOpen`
// (_tcp_seam.h): drive the DUT through a LISTEN-then-ACCEPT via the
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
    // Passive-OPEN cases require the DUT's TCP data plane (kCapTcpControl);
    // seamTcpControl asserts it (contract-guaranteed by the centralised
    // capability gate, Tier 2 2b#4 — a silent return here would mis-report as a
    // timeout FAIL, not a SKIP).
    int tester_fd = -1;
    auto conn = ::tc8::sce::seamTcpControl(dut).acceptTcp(
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

// Listen-only counterpart of driveSeamPassiveOpen: put the DUT into LISTEN on
// `listen_port` and hand back the listening socket handle, WITHOUT awaiting an
// accept (`ITcpControl::listenTcp`). For raw-inject cases that drive the DUT
// into LISTEN and then emit their own tester-side stimulus (invalid-flag SYNs,
// OTW RSTs, verify-probe ACKs) and verdict on the DUT's wire responses — the
// handshake never completes through the kernel, so there is no accept to
// confirm and hence no `trigger`/`tester_fd` (the case owns all stimulus). The
// caller closes the returned handle (`closeTcp`) when done.
//
// Mirrors driveSeamPassiveOpen's capability contract and ops diagnostic: the
// deref is guaranteed by the centralised capability gate (Tier 2 2b#4), the
// assert documents it, and a nullopt is logged with backend + port so a
// passive-open RPC failure is not mis-reported downstream as a DUT timeout.
inline std::optional<::tc8::sce::DutSocket> driveSeamListen(::tc8::sce::IDutControl &dut,
                                                            std::uint16_t listen_port) {
    auto handle = ::tc8::sce::seamTcpControl(dut).listenTcp(
        ::tc8::sce::BindSpec{/*do_bind=*/true, listen_port, /*local_addr_be=*/0});
    if (!handle) {
        std::fprintf(stderr,
                     "tcp-pilot: seam listen-only failed (listenTcp "
                     "listen=%u, backend=%s)\n",
                     listen_port, dut.backendName());
    }
    return handle;
}

// Result of driveSeamRawPassiveAccept. `conn` is the ACCEPTED DUT connection —
// the handle a case drives sendTcp / sendTcpPattern / closeTcp on after the
// handshake, or nullopt if the DUT never reached ESTABLISHED (no SYN+ACK, or the
// accept never confirmed). The seam abstracts the backend's accepted-socket
// model: the opcode UT promotes the LISTEN socket id in place to the accepted
// connection, while the testability LISTEN_AND_ACCEPT Event reports a distinct
// accepted-child socket id (the listening socket is closed inside acceptTcp).
// `dut_isn` is the DUT SYN+ACK seq_num the caller composes post-handshake tester
// segments off (ACKNOWLEDGEMENT_03, SEQUENCE_05); it is valid whenever `conn` is
// present (the accept only confirms after the handshake captured the SYN+ACK), so
// `conn.has_value()` is the single success predicate — no separate `ok` flag.
struct SeamRawPassiveAccept {
    std::optional<::tc8::sce::DutConnection> conn;
    std::uint32_t                            dut_isn = 0;
};

// Raw passive ACCEPT for cases that must operate on the ESTABLISHED connection
// after a caller-crafted passive handshake: open a DUT LISTEN, raw-inject a
// tester SYN whose options bytes the caller fully controls, complete the 3-way
// handshake, and hand back the ACCEPTED DUT connection.
//
// The whole open routes through ITcpControl::acceptTcp, so the accept
// confirmation IS the both-backend "reached ESTABLISHED" verdict (opcode: an
// OpQueryTcpEstablished poll on the accepted fd; testability: the
// LISTEN_AND_ACCEPT Event) — no state-probe capability is required, so the case
// runs and PASSes on whichever backend `--dut-control` selects. The crafted SYN
// is the acceptTcp `trigger` body: the real client whose handshake the DUT's
// SYN+ACK completes, exactly as connectToDutTcp is for driveSeamPassiveOpen.
//
// `tester_isn` pins the tester's SYN seq (default kTesterInitialSeq; the
// SEQUENCE cases override it — e.g. 0xFFFFFFFF for the modulo-32
// wraparound). The tester-side 3-way choreography is the shared SSOT
// rawPassiveThreeWayHandshake (tcp_pilot_common.h); only the seam LISTEN+ACCEPT
// open lives here. A nullopt `conn` (no DUT SYN+ACK, or the accept never
// confirmed) is the caller's failure / teardown gate.
inline SeamRawPassiveAccept driveSeamRawPassiveAccept(
    ::tc8::sce::IDutControl &dut, const ::tc8::TestConfig &cfg,
    std::string_view iface, std::uint16_t listen_port,
    std::vector<std::uint8_t> syn_options, std::uint16_t tester_src_port,
    std::uint32_t tester_isn = kTesterInitialSeq,
    std::chrono::milliseconds capture_timeout = std::chrono::milliseconds(2000)) {
    SeamRawPassiveAccept result{};
    std::optional<std::uint32_t> dut_isn;

    // The trigger moves syn_options into the handshake. This is safe because
    // acceptTcp's contract (ITcpControl, dut_socket_control.h) invokes the
    // trigger at most once, so the moved-from vector is never read again.
    result.conn = ::tc8::sce::seamTcpControl(dut).acceptTcp(
        ::tc8::sce::BindSpec{/*do_bind=*/true, listen_port, /*local_addr_be=*/0},
        [&] {
            dut_isn = rawPassiveThreeWayHandshake(
                cfg, iface, listen_port, std::move(syn_options), tester_src_port,
                tester_isn, capture_timeout);
        });

    if (dut_isn) result.dut_isn = *dut_isn;
    if (!result.conn) {
        std::fprintf(stderr,
                     "tcp-pilot: seam raw-passive ACCEPT failed (acceptTcp "
                     "listen=%u, backend=%s)\n",
                     listen_port, dut.backendName());
    }
    return result;
}

}  // namespace tc8::sce::tcp
