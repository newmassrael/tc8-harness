#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_time_wait_prelude.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_09_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09NegSM =
    ::SCE::Generated::tcp_flags_processing_09_neg::tcp_flags_processing_09_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_09 (CLOSING), per-fail-final variant 1 of 3:
// a conformant DUT in CLOSING absorbs a duplicate FIN+ACK without changing state or emitting a
// RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the
// prohibited RST on the connection 4-tuple when that FIN-bearing segment arrives (the FIN trips
// the disruptive-union gate), and the case passes only when that synthesized RST is observed.
// lwIP-only (kCapIngressFault). The watch is is_dut_rst ONLY: a conformant DUT legitimately
// emits a FIN/ACK in this close state, so watching for a DUT FIN would false-pass (session-17).
// A §4.8 must-not-respond case the ingress-synthesis seam reaches but the egress field-fault
// cannot — the conformant DUT emits no RST to corrupt.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing09NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_09_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_09 (CLOSING): the lwIP kTcpSynthRstOnDisruptive "
        "ingress flavor makes the DUT emit a RST to a duplicate FIN+ACK in CLOSING; a conformant "
        "DUT stays silent";

    // Mirrors the positive's CLOSING phase (TesterAutoAckDrop + seam active OPEN + seam
    // close-to-CLOSING), with the fault armed after the seam reaches CLOSING and before the
    // duplicate FIN+ACK inject, so only that segment elicits the synthesized RST. The duplicate
    // replays the helper-injected FIN (seq = tester_seq_post_fin - 1, ack = tester_ack_post_fin
    // - 1: acceptable but does NOT acknowledge the DUT FIN, so the DUT stays in CLOSING).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProc09NegClosingOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProc09NegClosingOffset;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        const auto info = driveSeamCloseToClosing(
            dut, cfg, iface, tester_fd, open.conn->socket, local_port, remote_port);
        if (info.ok) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec dup{};
            dup.src_port = remote_port;
            dup.dst_port = local_port;
            dup.seq_num  = info.tester_seq_post_fin - 1U;
            dup.ack_num  = info.tester_ack_post_fin - 1U;
            dup.flags    = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, dup, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09NegSM, tcp_flags_processing_09_neg)
