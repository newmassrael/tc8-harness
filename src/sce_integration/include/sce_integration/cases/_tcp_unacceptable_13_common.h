#pragma once

#include <array>
#include <chrono>
#include <cstdint>

#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_13 share. The case asks one question of a
// DUT parked in TIME-WAIT: given a data segment that is not acceptable, does it answer
// with an acknowledgement carrying the right SEQ and ACK, and stay where it is. The
// iterations differ in WHAT is unacceptable, and nothing else, so the stimulus is written
// once and the iteration says which segment to send.

namespace tc8::sce::cases {

enum class Unacceptable13Segment {
    // A data segment whose SEQ lies outside the receive window (the first iteration).
    kOutOfWindowSeq,
    // An in-window data segment whose ACK number acknowledges bytes the DUT never sent (the
    // second iteration).
    kUnacceptableAck,
};

inline constexpr std::array<std::uint8_t, 4> kUnacceptable13CorruptPayload = {0xCAU, 0xFEU,
                                                                              0xBAU, 0xBEU};

// One iteration: the FIN-WAIT-2 prelude over the Tier-2 seam (active OPEN, DUT CLOSE via
// closeTcp, tester ACK, tester FIN, DUT pure ACK) walks the DUT to TIME-WAIT and closes the
// tester fd, so the iteration's port quad is wholly available to the raw-injected segment;
// the prelude also captures the tester's snd_nxt / rcv_nxt at TIME-WAIT entry, the base of
// the corrupt segment's SEQ / ACK. `local_offset` is the iteration's port-quad offset, so the
// two iterations keep the wire identities they have always had.
inline void driveUnacceptable13Iteration(::tc8::TcpCaptured &c, const ::tc8::TestConfig &cfg,
                                         ::tc8::sce::StimulusContext &ctx,
                                         std::uint16_t local_offset, Unacceptable13Segment which) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    const auto info = driveSeamTimeWaitFw2(ctx.dut, cfg, local_port, remote_port);
    if (!info.ok) {
        return;
    }
    // The acknowledgement the DUT must send is a pure ACK with ack_num == the TIME-WAIT
    // socket's rcv_nxt == the tester's snd_nxt at TIME-WAIT entry (the corrupt segment is
    // discarded, so it does not move).
    c.expected_ack_num = info.tester_seq_post_fin;

    ::tc8::stimulus::TcpSegmentSpec data{};
    data.src_port = remote_port;
    data.dst_port = local_port;
    data.flags = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
    data.payload.assign(kUnacceptable13CorruptPayload.begin(), kUnacceptable13CorruptPayload.end());
    switch (which) {
        case Unacceptable13Segment::kOutOfWindowSeq:
            // SEQ outside the window, ACK acceptable.
            data.seq_num = info.tester_seq_post_fin + kOutOfWindowSeqOffset;
            data.ack_num = info.tester_ack_post_fin;
            break;
        case Unacceptable13Segment::kUnacceptableAck:
            // SEQ in the window, so the DUT's validation does not stop at the out-of-window
            // path before it examines the ACK; the ACK is beyond anything the DUT sent.
            data.seq_num = info.tester_seq_post_fin;
            data.ack_num = info.tester_ack_post_fin + kUnacceptableAckOffset;
            break;
    }
    emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, data, /*initial_wait=*/std::chrono::milliseconds(0));
}

}  // namespace tc8::sce::cases
