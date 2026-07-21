#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

// Shared prelude for the two §4.8.6.6 TCP_FLAGS_INVALID_05 must-move-to-CLOSED _NEG
// variants (phase 1 SYN+ACK+RST, phase 2 ACK+RST). Both drive the DUT into SYN-SENT via an
// active OPEN to an unbound tester port (no listener, so the SYN goes unanswered and the DUT
// stays in SYN-SENT), observe the DUT SYN, then arm kTcpDropDisruptiveRst and inject the
// RST-bearing probe carrying an acceptable ACK (ISN_d + 1). The armed flavor swallows the RST
// at the lwIP netif input so lwIP never moves to CLOSED and keeps retransmitting its SYN at the
// fixed 1 s cadence — the continued-SYN violation the positive's absence window forbids. The
// variants differ only in the per-phase active-OPEN port offset and the probe's flag set, so
// the prelude is factored here rather than duplicated across the two traits. lwIP-only
// (kCapIngressFault); the mirror reuses the positive's offsets so the 4-tuples cannot drift.
namespace tc8::sce::cases::flags_invalid_05_neg {

inline void driveSynSentRstDrop(::tc8::sce::IDutControl& dut,
                                const ::tc8::TestConfig& cfg,
                                std::string_view iface,
                                std::uint16_t port_offset,
                                std::uint8_t  probe_flags) {
    using namespace ::tc8::sce::tcp;
    std::this_thread::sleep_for(kTcpUtBootWait);

    TesterAutoRstDrop rst_drop(cfg);
    (void)rst_drop;

    const std::uint16_t local_port  = kBasicsActiveLocalPort  + port_offset;
    const std::uint16_t remote_port = kBasicsActiveRemotePort + port_offset;

    auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

    // Active OPEN routed through the backend-agnostic seam, no tester listener — the SYN goes
    // unanswered so the DUT stays in SYN-SENT, the state this case injects the RST into. The
    // handle is discarded (closing a SYN-SENT socket would abort the state under test).
    (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

    const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
    if (!syn.has_value()) return;

    // Per-phase arm: the DUT SYN has been observed (the SCXML precondition); arm so the drop
    // fires on the RST injected next. The eliciting inject carries the arm settle so the
    // raw-injected arm reaches the DUT UT thread before the RST reaches the netif input hook.
    emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpDropDisruptiveRst);

    // The RST carries ack = ISN_d + 1, the only acceptable ACK in SYN-SENT (SND.UNA = ISN_d,
    // SND.NXT = ISN_d + 1, RFC 793 §3.4) — the same probe shape the positive injects.
    ::tc8::stimulus::TcpSegmentSpec probe{};
    probe.src_port = remote_port;
    probe.dst_port = local_port;
    probe.seq_num  = kTesterInitialSeq;
    probe.ack_num  = syn->seq_num + 1U;
    probe.flags    = probe_flags;
    emitTcpFrame(cfg, iface, cfg.dut.mac, probe, /*initial_wait=*/kFlavorArmSettle);
}

}  // namespace tc8::sce::cases::flags_invalid_05_neg
