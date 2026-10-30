#pragma once

#include <chrono>
#include <cstdint>
#include <thread>

#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/tcp_captured.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_BASICS_05 share. The case asks one question of a DUT whose
// port is CLOSED: given a segment that carries ACK and not RST, does it answer with an RST
// whose SEQ is the incoming segment's ACK number. The iterations differ in WHICH flags carry
// that ACK, and nothing else, so the stimulus is written once and the iteration says which
// segment to send.
//
// The ACK number differs per iteration (kTesterPilotAckPhaseSynAck, kTesterPilotAckPhaseAck),
// so each iteration's pass guard pins a value of its own and a DUT that answers with one fixed
// SEQ cannot pass both. The tester-side SEQ differs per iteration too. It is irrelevant to the
// spec criterion (only ACK matters) but a DUT that mirrors SEQ instead of ACK then fails the
// SEQ conjunct loudly.

namespace tc8::sce::cases {

enum class Basics05Segment {
    // SYN and ACK together (the first iteration).
    kSynAck,
    // A bare ACK (the second iteration).
    kAck,
};

// One iteration: a single raw-injected segment to the closed port. No Upper Tester setup is
// needed, since CLOSED is the default state of a port nothing is bound to.
inline void driveBasics05Iteration(const ::tc8::TestConfig &cfg, ::tc8::sce::StimulusContext &ctx,
                                   Basics05Segment which) {
    using namespace ::tc8::sce::tcp;

    switch (which) {
        case Basics05Segment::kSynAck:
            emitTcpStimulus(cfg, ctx.iface, cfg.dut.mac,
                            /*dst_port=*/kBasicsClosedPort,
                            /*flags=*/
                            static_cast<std::uint8_t>(::tc8::stimulus::kTcpFlagSyn |
                                                      ::tc8::stimulus::kTcpFlagAck),
                            /*seq_num=*/kTesterInitialSeq,
                            /*ack_num=*/kTesterPilotAckPhaseSynAck);
            break;
        case Basics05Segment::kAck:
            emitTcpStimulus(cfg, ctx.iface, cfg.dut.mac,
                            /*dst_port=*/kBasicsClosedPort,
                            /*flags=*/::tc8::stimulus::kTcpFlagAck,
                            /*seq_num=*/kTesterInitialSeq + 0x100U,
                            /*ack_num=*/kTesterPilotAckPhaseAck);
            break;
    }
    std::this_thread::sleep_for(kTcpPilotPhaseGap);
}

}  // namespace tc8::sce::cases
