#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <thread>

#include <sys/socket.h>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_12 share. The case asks one question of a
// DUT parked in LAST-ACK: given a data segment that is not acceptable, does it answer with
// an empty acknowledgement carrying the right SEQ and ACK, and stay where it is. The
// iterations differ in WHAT is unacceptable, and nothing else, so the stimulus is written
// once and the iteration says which segment to send.

namespace tc8::sce::cases {

enum class Unacceptable12Segment {
    // A data segment whose SEQ lies outside the receive window (the first iteration).
    kOutOfWindowSeq,
    // An in-window data segment whose ACK number acknowledges bytes the DUT never sent (the
    // second iteration).
    kUnacceptableAck,
};

inline constexpr std::array<std::uint8_t, 4> kUnacceptable12CorruptPayload = {0xCAU, 0xFEU,
                                                                              0xBAU, 0xBEU};

// One iteration, backend-agnostic over the seam (opcode UT or AUTOSAR testability): the
// tester's pure ACKs suppressed (TesterAutoAckDrop) for the whole iteration, an active-OPEN
// handshake to ESTABLISHED, the tester's shutdown(WR) (its FIN+ACK, the DUT's auto-ACK
// observed, the DUT in CLOSE-WAIT), the seam close (the DUT's FIN+ACK observed; the
// tester's pure ACK to it is suppressed, which pins the DUT in LAST-ACK), a snapshot of the
// tester's SEQ/ACK, then the corrupt segment, and finally a silent close of the tester
// socket (TCP_REPAIR plus close, no FIN emitted, so the 4-tuple is freed cleanly).
// `local_offset` is the iteration's port-quad offset: each iteration leaves a LAST-ACK
// residue of about a minute, so the two offsets must differ from each other and from
// sibling TCP_UNACCEPTABLE_11, or a same-worker bind hits EADDRNOTAVAIL (the BASICS_11
// collision class, tcp_active_open_offsets.def).
inline void driveUnacceptable12Iteration(::tc8::TcpCaptured &c, const ::tc8::TestConfig &cfg,
                                         ::tc8::sce::StimulusContext &ctx,
                                         std::uint16_t local_offset, Unacceptable12Segment which) {
    using namespace ::tc8::sce::tcp;

    TesterAutoAckDrop ack_drop(cfg);
    (void)ack_drop;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
    const int tester_fd = acceptPreambleConnection(open);
    if (tester_fd < 0) {
        return;
    }
    if (!open.conn) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    ::shutdown(tester_fd, SHUT_WR);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    seamTcpControl(ctx.dut).closeTcp(open.conn->socket);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto seq_range = queryTcpSeqRange(tester_fd);
    if (!seq_range.has_value()) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    // The acknowledgement the DUT must send carries ack_num == the tester's snd_nxt at
    // injection: the tester's FIN advanced the DUT's rcv.nxt, and the corrupt segment is
    // discarded without moving it. Confirmed on the wire for both segments (the
    // out-of-window SEQ draws a duplicate ACK, the unacceptable ACK the explicit challenge
    // ACK LAST-ACK sends when the ACK is past snd_nxt).
    c.expected_ack_num = seq_range->snd_nxt;

    ::tc8::stimulus::TcpSegmentSpec data{};
    data.src_port = remote_port;
    data.dst_port = local_port;
    data.flags = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
    data.payload.assign(kUnacceptable12CorruptPayload.begin(), kUnacceptable12CorruptPayload.end());
    switch (which) {
        case Unacceptable12Segment::kOutOfWindowSeq:
            // SEQ outside the window; ACK = rcv_nxt - 1 is acceptable (inside snd.una..snd.nxt,
            // RFC 793 §3.4) and does NOT acknowledge the DUT's FIN, so the DUT stays in
            // LAST-ACK. Linux's out-of-window SEQ check fires before the ACK check, so the
            // answer is its duplicate ACK.
            data.seq_num = seq_range->snd_nxt + kOutOfWindowSeqOffset;
            data.ack_num = seq_range->rcv_nxt - 1U;
            break;
        case Unacceptable12Segment::kUnacceptableAck:
            // SEQ in the window, so validation does not stop at the out-of-window path before
            // it examines the ACK; the ACK is past anything the DUT sent. LAST-ACK is handled
            // by the receive state machine, which on an unacceptable ACK sends the challenge
            // ACK explicitly. The FIN-WAIT-2 orphan (TCP_UNACCEPTABLE_10) resets instead
            // (docs/tech-debt.md TD-31); ESTABLISHED (TCP_UNACCEPTABLE_04) dropped silently on
            // Linux 6.5 but answers on kernel 7.0 (see that SCXML's preamble).
            data.seq_num = seq_range->snd_nxt;
            data.ack_num = seq_range->rcv_nxt - 1U + kUnacceptableAckOffset;
            break;
    }
    emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, data, /*initial_wait=*/std::chrono::milliseconds(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    silentlyCloseTesterFd(tester_fd);
}

}  // namespace tc8::sce::cases
