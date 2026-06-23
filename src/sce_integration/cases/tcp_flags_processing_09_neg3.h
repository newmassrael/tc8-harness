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

#include "tcp_flags_processing_09_neg3_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09Neg3SM =
    ::SCE::Generated::tcp_flags_processing_09_neg3::tcp_flags_processing_09_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_09 (CLOSE-WAIT), per-fail-final variant 3 of 3:
// a conformant DUT in CLOSE-WAIT absorbs a duplicate FIN+ACK without changing state or emitting a
// RST (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP netif input hook synthesize the
// prohibited RST on the connection 4-tuple when that FIN-bearing segment arrives, and the case
// passes only when that synthesized RST is observed. lwIP-only (kCapIngressFault). The watch is
// is_dut_rst ONLY (session-17: a conformant DUT may legitimately emit a FIN here once its app
// closes). A §4.8 must-not-respond case the ingress-synthesis seam reaches but the egress
// field-fault cannot — the conformant DUT emits no RST to corrupt.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09Neg3SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing09Neg3SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_09_NEG3";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_09 (CLOSE-WAIT): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to a duplicate FIN+ACK "
        "in CLOSE-WAIT; a conformant DUT stays silent";

    // Mirrors the positive's CLOSE-WAIT phase (seam active OPEN + tester half-close -> DUT
    // CLOSE-WAIT; the DUT has not closed, so it stays in CW), with the fault armed before the
    // duplicate FIN+ACK inject. The duplicate replays the original tester FIN (seq = snd_nxt - 1,
    // ack = rcv_nxt: a valid dup ACK; the DUT must absorb it without responding).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProc09NegCloseWaitOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProc09NegCloseWaitOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0 || !open.conn) {
            silentlyCloseTesterFd(tester_fd);
            return;
        }
        ::shutdown(tester_fd, SHUT_WR);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec dup{};
            dup.src_port = remote_port;
            dup.dst_port = local_port;
            dup.seq_num  = seq_range->snd_nxt - 1U;
            dup.ack_num  = seq_range->rcv_nxt;
            dup.flags    = ::tc8::stimulus::kTcpFlagFin | ::tc8::stimulus::kTcpFlagAck;
            emitTcpFrame(cfg, iface, cfg.dut.mac, dup, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09Neg3SM, tcp_flags_processing_09_neg3)
