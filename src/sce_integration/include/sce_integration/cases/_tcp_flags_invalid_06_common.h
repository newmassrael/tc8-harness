#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_FLAGS_INVALID_06 share. The case asks one question of a
// DUT parked in SYN-SENT: given a segment with neither SYN nor RST whose ACK number is
// acceptable, does it drop the segment, stay silent and stay in SYN-SENT. The iterations
// differ in whether that segment carries data, and nothing else, so the stimulus is written
// once and the iteration says which probe to send.

namespace tc8::sce::cases {

enum class FlagsInvalid06Probe {
    // A bare ACK, no payload (the first iteration).
    kNoData,
    // An ACK carrying four bytes of payload (the second iteration).
    kWithData,
};

inline constexpr std::array<std::uint8_t, 4> kFlagsInvalid06ProbePayload = {0xDEU, 0xADU,
                                                                           0xBEU, 0xEFU};

// The probe: neither SYN nor RST, ack = ISN_d + 1 (the only value inside [SND.UNA, SND.NXT]
// for a SYN-SENT connection, so the ACK is acceptable), seq = the tester's initial sequence.
inline void emitFlagsInvalid06Probe(const ::tc8::TestConfig &cfg, std::string_view iface,
                                    std::uint16_t local_port, std::uint16_t remote_port,
                                    std::uint32_t isn_d, FlagsInvalid06Probe which) {
    ::tc8::stimulus::TcpSegmentSpec probe{};
    probe.src_port = remote_port;
    probe.dst_port = local_port;
    probe.seq_num = ::tc8::sce::tcp::kTesterInitialSeq;
    probe.ack_num = isn_d + 1U;
    probe.flags = ::tc8::stimulus::kTcpFlagAck;
    if (which == FlagsInvalid06Probe::kWithData) {
        probe.payload.assign(kFlagsInvalid06ProbePayload.begin(), kFlagsInvalid06ProbePayload.end());
    }
    ::tc8::sce::tcp::emitTcpFrame(cfg, iface, cfg.dut.mac, probe,
                                  /*initial_wait=*/std::chrono::milliseconds(0));
}

// One iteration: TesterAutoRstDrop scope, active OPEN to an unbound tester port (no
// listener, so the SYN stays unanswered and the DUT remains in SYN-SENT), ISN_d learned from
// the DUT's SYN on the case's own capture, then the probe. `local_offset` is the iteration's
// port-quad offset, so the two iterations keep the wire identities they have always had.
// The step runs in the stimulus, before the listen window.
inline void driveFlagsInvalid06Iteration(const ::tc8::TestConfig &cfg,
                                         ::tc8::sce::StimulusContext &ctx,
                                         std::uint16_t local_offset,
                                         FlagsInvalid06Probe which) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const ::tc8::sce::ObservationCursor armed = ctx.observer.mark();

    // Seam active OPEN, no tester listener: the SYN stays unanswered so the DUT remains in
    // SYN-SENT. Handle discarded (no closeTcp).
    (void)driveSeamSynSentOpen(ctx.dut, cfg, local_port, remote_port);

    const auto syn = ctx.observer.awaitObservation("dut_syn", armed, dutSynFrom(cfg.dut.ip, local_port),
                                                   std::chrono::milliseconds(500));
    if (syn.has_value()) {
        emitFlagsInvalid06Probe(cfg, ctx.iface, local_port, remote_port, segmentOf(syn->view()).seq_num,
                                which);
    }
}

}  // namespace tc8::sce::cases
