#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_unacceptable_10_neg_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable10NegSM =
    ::SCE::Generated::tcp_unacceptable_10_neg::tcp_unacceptable_10_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.3 TCP_UNACCEPTABLE_10: a conformant DUT in FIN-WAIT-2 MUST return an
// empty ACK (not a RST) to a segment carrying an unacceptable ACK and stay in FIN-WAIT-2 (RFC 793
// §3.4). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the prohibited RST on
// the connection's 4-tuple when the PSH-bearing unacc-ACK segment arrives, so the
// dut_rst_to_unacc_ack_finwait2 fail-final (is_dut_rst) is reachable; the case passes only when
// that synthesized RST is observed. lwIP-only (kCapIngressFault). The positive is a Linux
// known-deviation (Linux FW2 substate RSTs), but the lwIP fixture is conformant (positive passes),
// so this _neg is a faithful self-validation. Single fail-final, so no coverage.json entry.
template <>
struct TestCaseTraits<cases::TcpUnacceptable10NegSM>
    : TcpIngressFaultNegBase<cases::TcpUnacceptable10NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_UNACCEPTABLE_10_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_UNACCEPTABLE_10: the lwIP kTcpSynthRstOnDisruptive ingress flavor "
        "makes the DUT emit a RST to an unacceptable-ACK segment in FIN-WAIT-2; a conformant DUT "
        "returns an empty ACK";

    // Mirrors the positive's prelude (active OPEN -> ESTABLISHED -> DUT CLOSE -> FIN-WAIT-1 ->
    // tester auto-ACK -> FIN-WAIT-2), then arms the synth flavor and injects a single PSH-bearing
    // unacc-ACK segment so the hook fabricates the prohibited RST. Phase 1 (the OTW-SEQ data ACK)
    // is omitted: the synthesis is stateless and fires on the armed PSH gate, so reaching FIN-WAIT-2
    // and injecting one disruptive segment is sufficient to drive the phase-2 fail-final.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpUnacceptable10LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpUnacceptable10LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (open.conn) dut.tcpControl()->closeTcp(open.conn->socket);
        // Settle: the tester kernel auto-ACKs the DUT FIN (FIN-WAIT-1 -> FIN-WAIT-2) and the tester
        // socket TCP state stabilises before the TCP_REPAIR seq query.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (tester_fd < 0) return;

        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (!seq_range.has_value()) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }

        // Per-phase arm before the disruptive segment; the inject carries the arm settle so the
        // raw-injected arm reaches the DUT UT thread before the segment hits the netif input hook.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec unacc{};
        unacc.src_port = remote_port;
        unacc.dst_port = local_port;
        unacc.seq_num  = seq_range->snd_nxt;                          // in-window
        unacc.ack_num  = seq_range->rcv_nxt + kUnacceptableAckOffset;  // unacceptable ACK
        unacc.flags    = ::tc8::stimulus::kTcpFlagPsh | ::tc8::stimulus::kTcpFlagAck;
        // Filler payload — the synth-RST gate fires on the PSH flag, not the bytes, so this is not
        // an SSOT dependency on the positive's kCorruptPayload (a per-case member, not a shared
        // invariant); 4 bytes mirror the positive's data-segment shape for fidelity.
        unacc.payload  = std::vector<std::uint8_t>{0xCAU, 0xFEU, 0xBAU, 0xBEU};
        emitTcpFrame(cfg, iface, cfg.dut.mac, unacc, /*initial_wait=*/kFlavorArmSettle);

        std::this_thread::sleep_for(kSynthObserveHold);
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable10NegSM, tcp_unacceptable_10_neg)
