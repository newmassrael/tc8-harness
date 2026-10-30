#pragma once

#include <chrono>
#include <cstdint>
#include <thread>

#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_config.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_05 share. The case asks one question of a DUT
// in LISTEN: given a segment carrying an ACK, which acknowledges something the DUT never
// sent, does it answer with an RST. The iterations differ in WHICH flags the segment carries
// and nothing else, so the stimulus is written once and the iteration says which segment to
// send.
//
// The "unacceptable ACK number" in LISTEN is any non-zero ACK: LISTEN has sent no bytes, so
// any positive ACK is acknowledging something never sent. kTesterInitialSeq + 1 is an
// arbitrary non-zero literal.

namespace tc8::sce::cases {

// One iteration: a seam listen-only open on `listen_port` (ITcpControl::listenTcp), so the
// case runs on whichever backend `--dut-control` selected, the tester's raw segment with
// `flags` and `seq_num`, and the seam close of the listener. Each iteration has its own DUT
// listener port, so an iteration's RST emission cannot reach the other's listen window and
// its listener bind cannot collide with the other's still-being-closed listener.
inline void driveUnacceptable05Iteration(const ::tc8::TestConfig &cfg,
                                         ::tc8::sce::StimulusContext &ctx,
                                         std::uint16_t listen_port, std::uint8_t flags,
                                         std::uint32_t seq_num) {
    using namespace ::tc8::sce::tcp;

    const auto listen = driveSeamListen(ctx.dut, listen_port);
    if (!listen) return;

    ::tc8::stimulus::TcpSegmentSpec seg{};
    seg.src_port = kBasicsTesterPort;
    seg.dst_port = listen_port;
    seg.seq_num = seq_num;
    seg.ack_num = kTesterInitialSeq + 1U;
    seg.flags = flags;
    emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, seg);
    std::this_thread::sleep_for(kTcpPilotPhaseGap);

    ctx.dut.tcpControl()->closeTcp(*listen);
}

}  // namespace tc8::sce::cases
