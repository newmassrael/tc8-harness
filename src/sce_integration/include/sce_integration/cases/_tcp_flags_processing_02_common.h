#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>

#include <sys/socket.h>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body the five iterations of TCP_FLAGS_PROCESSING_02 share. The case asks one question
// of a DUT whose connection is in a given state: after an in-window RST, has it gone to
// CLOSED. The wire cannot show a state, so each iteration follows the RST with a verify-probe
// ACK on the same 4-tuple; a DUT that destroyed the connection answers it with an RST. The
// iterations differ in the state the DUT is walked into before the RST, and nothing else, so
// the RST and the probe are written once and the iteration says which state to drive.

namespace tc8::sce::cases {

// Spec-prescribed RST inject (RST+ACK with in-window seq).
inline void flagsProcessing02EmitRst(const ::tc8::TestConfig& cfg, std::string_view iface,
                                     std::uint16_t src_port, std::uint16_t dst_port,
                                     std::uint32_t seq_value, std::uint32_t ack_value) {
    ::tc8::stimulus::TcpSegmentSpec rst{};
    rst.src_port = src_port;
    rst.dst_port = dst_port;
    rst.seq_num  = seq_value;
    rst.ack_num  = ack_value;
    rst.flags    = ::tc8::stimulus::kTcpFlagRst | ::tc8::stimulus::kTcpFlagAck;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, rst,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

// Verify-probe ACK on the killed 4-tuple. If the DUT honoured the RST, the socket is gone and
// Linux's tcp_v4_send_reset (or LISTEN's tcp_rcv_state_process return-1 path for SYN-RCVD)
// emits a RST. seq/ack are arbitrary: Linux ignores them when emitting RST(seq=incoming.ack)
// on no-socket / LISTEN-routed paths.
inline void flagsProcessing02EmitVerifyAck(const ::tc8::TestConfig& cfg, std::string_view iface,
                                           std::uint16_t src_port, std::uint16_t dst_port,
                                           std::uint32_t seq_value, std::uint32_t ack_value) {
    ::tc8::stimulus::TcpSegmentSpec ack{};
    ack.src_port = src_port;
    ack.dst_port = dst_port;
    ack.seq_num  = seq_value;
    ack.ack_num  = ack_value;
    ack.flags    = ::tc8::stimulus::kTcpFlagAck;
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, ack,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

// The states reached through an active-OPEN connection. SYN-RCVD is not among them: it has
// no connection handle and is driven by its own function below.
enum class FlagsProcessing02State {
    // Active OPEN, no DUT close.
    kEstablished,
    // The DUT CLOSEs and the tester's pure ACKs are suppressed, so its FIN stays unacked and
    // the DUT stays in FIN-WAIT-1 across the verify probe.
    kFinWait1,
    // The DUT CLOSEs and the tester kernel's auto-ACK advances it FIN-WAIT-1 -> FIN-WAIT-2;
    // no shutdown(WR) follows, so the DUT stops at FIN-WAIT-2 rather than proceeding to
    // TIME-WAIT. The 200 ms settle lets that ACK land before the verify probe.
    kFinWait2,
    // The tester shutdown(WR)s, so the DUT enters CLOSE-WAIT; the DUT does not close.
    kCloseWait,
};

// SYN-RCVD: the DUT is put into LISTEN through the listen-only seam verb (driveSeamListen), a
// tester SYN draws the SYN+ACK, and the spec RST kills the half-open request. No accept ever
// completes, so there is no handle to close; the listen socket is reclaimed at END_TEST.
inline void driveFlagsProcessing02SynRcvd(const ::tc8::TestConfig& cfg,
                                          ::tc8::sce::StimulusContext& ctx) {
    using namespace ::tc8::sce::tcp;
    constexpr std::uint16_t kListenPort = kBasicsListenPort + 12U;
    constexpr std::uint16_t kTesterPort = kBasicsTesterPort + 76U;
    const std::string_view iface = ctx.iface;

    if (!driveSeamListen(ctx.dut, kListenPort)) return;

    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const ::tc8::sce::ObservationCursor armed = ctx.observer.mark();

    ::tc8::stimulus::TcpSegmentSpec syn{};
    syn.src_port = kTesterPort;
    syn.dst_port = kListenPort;
    syn.seq_num  = kTesterInitialSeq;
    syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
    emitTcpFrame(cfg, iface, cfg.dut.mac, syn,
                 /*initial_wait=*/std::chrono::milliseconds(0));

    const auto synack = ctx.observer.awaitObservation(
        "dut_syn_ack", armed, dutSynAckTo(cfg.dut.ip, kTesterPort),
        std::chrono::milliseconds(500));
    if (!synack.has_value()) return;

    // Spec RST: seq = ISN_t + 1 (= req->rsk_rcv_nxt expected next byte from tester after SYN
    // consumed +1). ack = ISN_d + 1 (acceptable). Linux's tcp_check_req drops the req_sock
    // for an in-seq RST.
    flagsProcessing02EmitRst(cfg, iface, kTesterPort, kListenPort, kTesterInitialSeq + 1U,
                             segmentOf(synack->view()).seq_num + 1U);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify-probe ACK. Routes to LISTEN; tcp_rcv_state_process returns 1 -> DUT RST.
    flagsProcessing02EmitVerifyAck(cfg, iface, kTesterPort, kListenPort, kTesterInitialSeq + 5U,
                                   segmentOf(synack->view()).seq_num + 1U);
}

// One iteration over an active-OPEN connection: handshake to ESTABLISHED, the state-specific
// drive, a snapshot of the tester's SEQ/ACK, then the RST and the verify probe.
// `local_offset` is the iteration's port-quad offset, so each iteration keeps the wire
// identity it has always had.
inline void driveFlagsProcessing02Connected(const ::tc8::TestConfig& cfg,
                                            ::tc8::sce::StimulusContext& ctx,
                                            std::uint16_t local_offset,
                                            FlagsProcessing02State which) {
    using namespace ::tc8::sce::tcp;
    const std::string_view iface = ctx.iface;
    const std::uint16_t local_port  = kBasicsActiveLocalPort  + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    // FIN-WAIT-1 holds the DUT FIN unacked for the whole stimulus, so the suppression is armed
    // before the handshake.
    std::optional<TesterAutoAckDrop> ack_drop;
    if (which == FlagsProcessing02State::kFinWait1) {
        ack_drop.emplace(cfg);
    }

    auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
    const int tester_fd = acceptPreambleConnection(open);
    switch (which) {
        case FlagsProcessing02State::kEstablished:
            if (tester_fd < 0) return;
            break;
        case FlagsProcessing02State::kFinWait1:
            if (tester_fd < 0 || !open.conn) {
                silentlyCloseTesterFd(tester_fd);
                return;
            }
            // DUT CLOSE -> DUT FIN; the tester AckDrop holds it unacked.
            ctx.dut.tcpControl()->closeTcp(open.conn->socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            break;
        case FlagsProcessing02State::kFinWait2:
            // The DUT CLOSE emits the DUT FIN, and the tester kernel's auto-ACK (no AckDrop
            // here, unlike the FW1 iteration) advances the DUT to FIN-WAIT-2.
            if (tester_fd < 0 || !open.conn) {
                silentlyCloseTesterFd(tester_fd);
                return;
            }
            ctx.dut.tcpControl()->closeTcp(open.conn->socket);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            break;
        case FlagsProcessing02State::kCloseWait:
            if (tester_fd < 0) return;
            ::shutdown(tester_fd, SHUT_WR);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            break;
    }

    const auto seq_range = queryTcpSeqRange(tester_fd);
    if (!seq_range.has_value()) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }
    flagsProcessing02EmitRst(cfg, iface, remote_port, local_port, seq_range->snd_nxt,
                             seq_range->rcv_nxt);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    flagsProcessing02EmitVerifyAck(cfg, iface, remote_port, local_port, seq_range->snd_nxt + 5U,
                                   seq_range->rcv_nxt);
    silentlyCloseTesterFd(tester_fd);
}

}  // namespace tc8::sce::cases
