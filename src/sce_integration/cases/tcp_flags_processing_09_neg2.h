#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <sys/socket.h>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_09_neg2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09Neg2SM =
    ::SCE::Generated::tcp_flags_processing_09_neg2::tcp_flags_processing_09_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_09 (LAST-ACK), per-fail-final variant 2 of 3:
// a conformant DUT in LAST-ACK absorbs a duplicate FIN+ACK without changing state or emitting a
// RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the
// prohibited RST on the connection 4-tuple when that FIN-bearing segment arrives, and the case
// passes only when that synthesized RST is observed. lwIP-only (kCapIngressFault). The watch is
// is_dut_rst ONLY (session-17: a conformant DUT legitimately emits a FIN in this close state).
// A §4.8 must-not-respond case the ingress-synthesis seam reaches but the egress field-fault
// cannot — the conformant DUT emits no RST to corrupt.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing09Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_09_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_09 (LAST-ACK): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to a duplicate FIN+ACK "
        "in LAST-ACK; a conformant DUT stays silent";

    // Mirrors the positive's LAST-ACK phase (TesterAutoAckDrop + seam active OPEN + tester
    // half-close -> DUT CLOSE-WAIT + DUT closeTcp -> LAST-ACK, AckDrop holding it there), with
    // the fault armed before the duplicate FIN+ACK inject. The duplicate replays the original
    // tester FIN (seq = snd_nxt - 1, ack = rcv_nxt - 1: acceptable but does NOT acknowledge the
    // DUT FIN, so the DUT stays in LAST-ACK).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProc09NegLastAckOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProc09NegLastAckOffset;

        TesterAutoAckDrop ack_drop(cfg);
        (void)ack_drop;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        dut.tcpControl()->closeTcp(open.conn->socket);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec dup{};
            dup.src_port = remote_port;
            dup.dst_port = local_port;
            dup.seq_num  = seq_range->snd_nxt - 1U;
            dup.ack_num  = seq_range->rcv_nxt - 1U;
            dup.flags    = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, dup, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09Neg2SM, tcp_flags_processing_09_neg2)
