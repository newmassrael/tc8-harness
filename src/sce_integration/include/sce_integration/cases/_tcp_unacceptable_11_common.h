#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <thread>

#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_11 share. The case asks one question of a
// DUT parked in CLOSING: given a data segment that is not acceptable, does it answer with an
// empty acknowledgement carrying the right SEQ and ACK, and stay where it is. The
// iterations differ in WHAT is unacceptable, and nothing else, so the stimulus is written
// once and the iteration says which segment to send.

namespace tc8::sce::cases {

enum class Unacceptable11Segment {
    // A data segment whose SEQ lies outside the receive window (the first iteration).
    // Linux's OTW-SEQ branch of tcp_validate_incoming fires before tcp_ack, so the challenge
    // ACK is observed.
    kOutOfWindowSeq,
    // An in-window data segment whose ACK number acknowledges bytes the DUT never sent (the
    // second iteration). The CLOSING handler answers it with a duplicate ACK on the data
    // path, where ESTABLISHED, FIN-WAIT-2 and LAST-ACK drop it in the tcp_ack short-circuit.
    kUnacceptableAck,
};

inline constexpr std::array<std::uint8_t, 4> kUnacceptable11CorruptPayload = {0xCAU, 0xFEU,
                                                                              0xBAU, 0xBEU};

// One iteration, on the Tier-2 DUT-control seam so it runs unchanged on whichever backend
// --dut-control selected: active OPEN via driveSeamActiveOpen, the DUT CLOSE and the
// non-acking tester FIN+ACK that drives it FW1 -> CLOSING via driveSeamCloseToClosing, then
// the corrupt segment. The tester-side AutoAckDrop, the corrupt probe and the silent dispose
// stay case-owned. `local_offset` is the iteration's port-quad offset: each iteration
// closes the DUT through CLOSING to LAST-ACK, leaving a ~60 s LAST_ACK residue, so the two
// offsets must differ from each other AND from sibling UNACCEPTABLE_12 or a same-worker bind
// hits EADDRNOTAVAIL (the BASICS_11 collision class, tcp_active_open_offsets.def).
inline void driveUnacceptable11Iteration(::tc8::TcpCaptured &c, const ::tc8::TestConfig &cfg,
                                         ::tc8::sce::StimulusContext &ctx,
                                         std::uint16_t local_offset, Unacceptable11Segment which) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    TesterAutoAckDrop ack_drop(cfg);
    (void)ack_drop;

    auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
    const int tester_fd = acceptPreambleConnection(open);
    if (tester_fd < 0 || !open.conn) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    const auto info = driveSeamCloseToClosing(ctx.dut, cfg, ctx.iface, tester_fd,
                                              open.conn->socket, local_port, remote_port);
    if (!info.ok) {
        silentlyCloseTesterFd(tester_fd);
        return;
    }

    // The criterion asks for an acknowledgement carrying the right sequence and ack numbers:
    // the DUT emits a pure ACK on the data path with ack_num == DUT.rcv.nxt at injection.
    // CLOSING was reached via the tester FIN consuming a virtual byte, so DUT.rcv.nxt ==
    // tester.snd_nxt == info.tester_seq_post_fin.
    c.expected_ack_num = info.tester_seq_post_fin;

    ::tc8::stimulus::TcpSegmentSpec data{};
    data.src_port = remote_port;
    data.dst_port = local_port;
    data.flags = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
    data.payload.assign(kUnacceptable11CorruptPayload.begin(), kUnacceptable11CorruptPayload.end());
    switch (which) {
        case Unacceptable11Segment::kOutOfWindowSeq:
            // The ACK is acceptable, so it does not trip the tcp_ack short-circuit.
            data.seq_num = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
            data.ack_num = info.tester_ack_post_fin;
            break;
        case Unacceptable11Segment::kUnacceptableAck:
            // SEQ in the window, so the DUT's validation does not stop at the out-of-window
            // path before it examines the ACK; the ACK is beyond anything the DUT sent.
            data.seq_num = info.tester_seq_post_fin;
            data.ack_num = info.tester_ack_post_fin + kUnacceptableAckOffset;
            break;
    }
    emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, data, /*initial_wait=*/std::chrono::milliseconds(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // TCP_REPAIR + close, no tester FIN emitted: frees the 4-tuple cleanly.
    silentlyCloseTesterFd(tester_fd);
}

}  // namespace tc8::sce::cases
