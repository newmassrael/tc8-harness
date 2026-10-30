#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body the iterations of TCP_BASICS_04 share. The case asks one question of a DUT whose
// port is CLOSED: given a segment that carries neither RST nor ACK, does it answer with an RST
// whose SEQ is zero. The iterations differ in WHAT the segment is, and nothing else, so the
// stimulus is written once and the iteration says which segment to send.

namespace tc8::sce::cases {

enum class Basics04Segment {
    // A bare SYN (the first iteration).
    kSyn,
    // A bare FIN (the second iteration).
    kFin,
    // A segment with no control bits set that carries data (the third iteration).
    kData,
};

// A small fixed body: a "Data segment" is a segment that carries data. Linux reaches the same
// reset path whatever the payload, but a non-empty body asserts the literal at the wire level
// instead of re-running the bare-flag exercise under a different name.
inline constexpr std::array<std::uint8_t, 4> kBasics04DataPayload = {0xAAU, 0xBBU, 0xCCU, 0xDDU};

// One iteration: a single raw-injected segment to the closed port. No Upper Tester setup is
// needed, since CLOSED is the default state of a port nothing is bound to. The tester-side SEQ
// literals differ per iteration so the segments stay distinguishable in a pcap, and ack_num is
// left at 0, since a segment whose ACK bit is clear has no ACK semantics whatever the field
// holds and a non-zero literal would mislead on inspection.
inline void driveBasics04Iteration(const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx,
                                   Basics04Segment which) {
    using namespace ::tc8::sce::tcp;

    switch (which) {
        case Basics04Segment::kSyn:
            emitTcpStimulus(cfg, ctx.iface, cfg.dut.mac,
                            /*dst_port=*/kBasicsClosedPort,
                            /*flags=*/::tc8::stimulus::kTcpFlagSyn,
                            /*seq_num=*/kTesterInitialSeq,
                            /*ack_num=*/0U);
            break;
        case Basics04Segment::kFin:
            emitTcpStimulus(cfg, ctx.iface, cfg.dut.mac,
                            /*dst_port=*/kBasicsClosedPort,
                            /*flags=*/::tc8::stimulus::kTcpFlagFin,
                            /*seq_num=*/kTesterInitialSeq + 0x100U,
                            /*ack_num=*/0U);
            break;
        case Basics04Segment::kData:
            emitTcpStimulus(cfg, ctx.iface, cfg.dut.mac,
                            /*dst_port=*/kBasicsClosedPort,
                            /*flags=*/0U,
                            /*seq_num=*/kTesterInitialSeq + 0x200U,
                            /*ack_num=*/0U,
                            /*payload=*/
                            std::vector<std::uint8_t>(kBasics04DataPayload.begin(),
                                                      kBasics04DataPayload.end()));
            break;
    }
    std::this_thread::sleep_for(kTcpPilotPhaseGap);
}

}  // namespace tc8::sce::cases
