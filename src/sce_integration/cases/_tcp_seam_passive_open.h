#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

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
    ::tc8::sce::ITcpControl *tcp = dut.tcpControl();
    assert(tcp != nullptr && "passive-OPEN cases require kCapTcpControl");

    auto handle = tcp->listenTcp(
        ::tc8::sce::BindSpec{/*do_bind=*/true, listen_port, /*local_addr_be=*/0});
    if (!handle) {
        std::fprintf(stderr,
                     "tcp-pilot: seam listen-only failed (listenTcp "
                     "listen=%u, backend=%s)\n",
                     listen_port, dut.backendName());
    }
    return handle;
}

// Result of driveSeamRawPassiveHandshake. `listen` is the DUT LISTEN handle the
// caller closes (closeTcp); `ut_established` is the kCapTcpStateProbe verdict
// byte (0xFF = query failed / handshake never landed, 0x00 = not established,
// 0x01 = established) — same encoding the opcode OpQueryTcpEstablished helper
// used.
struct SeamRawPassiveHandshake {
    std::optional<::tc8::sce::DutSocket> listen;
    std::uint8_t                         ut_established = 0xFFU;
};

// Seam counterpart of driveRawPassiveHandshake (tcp_pilot_common.h): open a DUT
// LISTEN via the listen-only seam verb, raw-inject a tester SYN whose options
// bytes the caller fully controls, complete the 3-way handshake, then confirm
// the DUT reached ESTABLISHED via the kCapTcpStateProbe sub-interface. Used by
// the MSS_OPTIONS verify phases (a hand-crafted SYN that must not
// disturb the kernel's TCP stack, proven by a clean follow-up handshake).
//
// Because the established check reads kernel socket state — opcode-only — a
// case using this MUST declare kRequiredCapabilities |= kCapTcpStateProbe so
// the CLI gate SKIPs it on a testability backend (Tier 2 2b#4); the
// tcpStateProbe() deref is then contract-guaranteed. The caller closes the
// returned listen handle once it has read ut_established. A nullopt `listen` or
// a missing DUT SYN+ACK leaves ut_established at 0xFF.
inline SeamRawPassiveHandshake driveSeamRawPassiveHandshake(
    ::tc8::sce::IDutControl &dut, const ::tc8::TestConfig &cfg,
    std::string_view iface, std::uint16_t listen_port,
    std::vector<std::uint8_t> syn_options, std::uint16_t tester_src_port,
    std::chrono::milliseconds capture_timeout = std::chrono::milliseconds(2000)) {
    SeamRawPassiveHandshake info{};
    info.listen = driveSeamListen(dut, listen_port);
    if (!info.listen) return info;

    auto snippet = TcpFrameSnippet::forDutSynAck(cfg, iface, tester_src_port);
    if (!snippet.ok()) return info;

    TesterAutoRstDrop rst_drop(cfg);

    ::tc8::stimulus::TcpSegmentSpec syn_spec{};
    syn_spec.src_port = tester_src_port;
    syn_spec.dst_port = listen_port;
    syn_spec.seq_num  = kTesterInitialSeq;
    syn_spec.flags    = ::tc8::stimulus::kTcpFlagSyn;
    syn_spec.options  = std::move(syn_options);
    emitTcpFrame(cfg, iface, cfg.dut.mac, syn_spec);

    const auto syn_ack = snippet.tryCapture(capture_timeout);
    if (!syn_ack) return info;

    ::tc8::stimulus::TcpSegmentSpec ack_spec{};
    ack_spec.src_port = tester_src_port;
    ack_spec.dst_port = listen_port;
    ack_spec.seq_num  = kTesterInitialSeq + 1U;
    ack_spec.ack_num  = syn_ack->seq_num + 1U;
    ack_spec.flags    = ::tc8::stimulus::kTcpFlagAck;
    emitTcpFrame(cfg, iface, cfg.dut.mac, ack_spec);

    // Settle so the kernel's accept queue drains and the established child is
    // visible to the state probe (mirrors driveRawPassiveHandshake's 50 ms).
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const auto est = dut.tcpStateProbe()->isEstablished(*info.listen);
    info.ut_established = static_cast<std::uint8_t>(
        !est.has_value() ? 0xFFU : (*est ? 0x01U : 0x00U));
    return info;
}

}  // namespace tc8::sce::tcp
