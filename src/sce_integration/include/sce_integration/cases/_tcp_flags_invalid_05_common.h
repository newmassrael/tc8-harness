#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_FLAGS_INVALID_05 share. The case asks one question of a DUT
// parked in SYN-SENT: given an RST that carries an acceptable ACK, does it move to CLOSED, which
// shows on the wire as its SYN retransmit stopping. The iterations differ in the flag set that
// rides with the RST (SYN,ACK or ACK) and nothing else, so the stimulus is written once and the
// iteration says which flags to send.

namespace tc8::sce::cases {

// One iteration: the DUT's active open is left in SYN-SENT (no tester listener, so the SYN stays
// unanswered), its SYN is learned from the case's own capture, and an RST carrying
// ack = ISN_d + 1 is injected. That is the only acceptable ACK in SYN-SENT: SND.UNA = ISN_d and
// SND.NXT = ISN_d + 1 (RFC 793 §3.4). `local_offset` is the iteration's port-quad offset, so each
// iteration keeps a wire identity of its own.
inline void driveFlagsInvalid05Iteration(::tc8::sce::IDutControl &dut,
                                         ::tc8::sce::IStimulusObserver &observer,
                                         const ::tc8::TestConfig &cfg, std::string_view iface,
                                         std::uint16_t local_offset, std::uint8_t probe_flags) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const ::tc8::sce::ObservationCursor armed = observer.mark();

    // Seam active OPEN, no tester listener: the SYN stays unanswered so the DUT remains in
    // SYN-SENT. Handle discarded (no closeTcp).
    (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

    const auto syn = observer.awaitObservation("dut_syn", armed, dutSynFrom(cfg.dut.ip, local_port),
                                               std::chrono::milliseconds(500));
    if (!syn.has_value()) {
        return;
    }
    ::tc8::stimulus::TcpSegmentSpec probe{};
    probe.src_port = remote_port;
    probe.dst_port = local_port;
    probe.seq_num = kTesterInitialSeq;
    probe.ack_num = segmentOf(syn->view()).seq_num + 1U;
    probe.flags = probe_flags;
    emitTcpFrame(cfg, iface, cfg.dut.mac, probe, /*initial_wait=*/std::chrono::milliseconds(0));
}

}  // namespace tc8::sce::cases
