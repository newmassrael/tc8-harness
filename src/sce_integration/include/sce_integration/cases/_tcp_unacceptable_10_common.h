#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <thread>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_10 share. The case asks one question of a
// DUT parked in FIN-WAIT-2: given a data segment that is not acceptable, does it answer
// with an empty acknowledgement carrying the right SEQ and ACK, and stay where it is. The
// iterations differ in WHAT is unacceptable, and nothing else, so the stimulus is written
// once and the iteration says which segment to send.

namespace tc8::sce::cases {

enum class Unacceptable10Segment {
    // A data segment whose SEQ lies outside the receive window (the first iteration).
    kOutOfWindowSeq,
    // An in-window data segment whose ACK number acknowledges bytes the DUT never sent (the
    // second iteration).
    kUnacceptableAck,
};

inline constexpr std::array<std::uint8_t, 4> kUnacceptable10CorruptPayload = {0xCAU, 0xFEU,
                                                                              0xBAU, 0xBEU};

// One iteration: active-OPEN handshake to ESTABLISHED, the DUT's CLOSE, the tester kernel's
// ACK of the DUT's FIN left to happen (it is what advances the DUT from FIN-WAIT-1 to
// FIN-WAIT-2), a snapshot of the tester's SEQ/ACK, then the corrupt segment. `local_offset`
// is the iteration's port-quad offset, so each iteration keeps a wire identity of its own.
inline void driveUnacceptable10Iteration(::tc8::sce::StimulusContext &ctx,
                                         const ::tc8::TestConfig &cfg, std::uint16_t local_offset,
                                         Unacceptable10Segment which) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    auto open = driveSeamActiveOpen(ctx.dut, cfg, local_port, remote_port);
    const int tester_fd = acceptPreambleConnection(open);
    if (open.conn) {
        ctx.dut.tcpControl()->closeTcp(open.conn->socket);
    }
    // The settle covers the auto-ACK round trip and the tester socket's TCP state
    // stabilising before the sequence state is read.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    if (tester_fd < 0) {
        return;
    }
    const auto seq_range = queryTcpSeqRange(tester_fd);
    if (!seq_range.has_value()) {
        return;
    }

    ::tc8::stimulus::TcpSegmentSpec data{};
    data.src_port = remote_port;
    data.dst_port = local_port;
    data.flags = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
    data.payload.assign(kUnacceptable10CorruptPayload.begin(), kUnacceptable10CorruptPayload.end());
    switch (which) {
        case Unacceptable10Segment::kOutOfWindowSeq:
            data.seq_num = seq_range->snd_nxt + kOutOfWindowSeqOffset;
            data.ack_num = seq_range->rcv_nxt;
            break;
        case Unacceptable10Segment::kUnacceptableAck:
            // SEQ in the window, so the DUT's validation does not stop at the out-of-window
            // path before it examines the ACK; the ACK is beyond anything the DUT sent.
            data.seq_num = seq_range->snd_nxt;
            data.ack_num = seq_range->rcv_nxt + kUnacceptableAckOffset;
            break;
    }
    emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, data, /*initial_wait=*/std::chrono::milliseconds(0));
}

}  // namespace tc8::sce::cases
