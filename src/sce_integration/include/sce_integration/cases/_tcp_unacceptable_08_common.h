#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_config.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// The body both iterations of TCP_UNACCEPTABLE_08 share. The case asks one question of a
// DUT parked in SYN-SENT: given a segment whose ACK acknowledges bytes the DUT never sent,
// does it answer with a RST. The iterations differ in the flags of that segment, and
// nothing else, so the stimulus is written once and the iteration says which flags to send.

namespace tc8::sce::cases {

// One iteration: the tester's kernel RST suppressed, the DUT's active open left in SYN-SENT
// (no tester listener), the DUT's SYN learned for its initial sequence number, then the
// unacceptable-ACK segment with `bad_inject_flags`. `local_offset` is the iteration's
// port-quad offset, so the two iterations keep the wire identities they have always had.
inline void driveUnacceptable08Iteration(::tc8::sce::IDutControl &dut,
                                         ::tc8::sce::IStimulusObserver &observer,
                                         const ::tc8::TestConfig &cfg, std::string_view iface,
                                         std::uint16_t local_offset,
                                         std::uint8_t bad_inject_flags) {
    using namespace ::tc8::sce::tcp;

    const std::uint16_t local_port = kBasicsActiveLocalPort + local_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + local_offset;

    // Without the suppression the tester kernel answers the DUT's SYN with a RST and the DUT
    // leaves SYN-SENT before the segment under test arrives.
    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const ::tc8::sce::ObservationCursor armed = observer.mark();

    // Seam active OPEN, no tester listener: the SYN stays unanswered so the DUT remains in
    // SYN-SENT, the state the unacceptable-ACK segment is injected into.
    auto open = driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

    const auto syn = observer.awaitObservation("dut_syn", armed, dutSynFrom(cfg.dut.ip, local_port),
                                               std::chrono::milliseconds(500));
    if (syn.has_value()) {
        // The unacceptable-ACK segment: ack = ISN_d + a large offset, acknowledging bytes
        // the DUT never sent.
        ::tc8::stimulus::TcpSegmentSpec bad{};
        bad.src_port = remote_port;
        bad.dst_port = local_port;
        bad.seq_num = kTesterInitialSeq;
        bad.ack_num = segmentOf(syn->view()).seq_num + kUnacceptableAckOffset;
        bad.flags = bad_inject_flags;
        emitTcpFrame(cfg, iface, cfg.dut.mac, bad, /*initial_wait=*/std::chrono::milliseconds(0));
        std::this_thread::sleep_for(kTcpPilotPhaseGap);
    }

    // A graceful close is right here and the teardown is NOT this case's problem, though it
    // looked like it: measured 2026-09-25, this close was answered 3.47 s after it was issued
    // and the next open timed out behind it. Swapping in `abortTcp` changed nothing, because
    // both verbs reach the same `tearDownSlot`, which JOINS a worker still sitting inside
    // connect(). The fix was to make `shutdown(RDWR)` on a SYN_SENT pcb actually unblock that
    // connect on the lwIP backend — the contract the shared teardown already assumed. See
    // docs/tech-debt.md TD-24.
    if (open) dut.tcpControl()->closeTcp(open->socket);
}

}  // namespace tc8::sce::cases
