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

#include "tcp_flags_processing_07_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing07NegSM =
    ::SCE::Generated::tcp_flags_processing_07_neg::tcp_flags_processing_07_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_07 phase 1 (CLOSE-WAIT): a conformant DUT in
// CLOSE-WAIT silently ignores a URG-only segment (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST on the connection's 4-tuple when the
// URG-only segment arrives (the disruptive-flag gate fires on URG), and the case passes only
// when that synthesized RST is observed. lwIP-only (kCapIngressFault). One of the four
// per-fail-final variants graduating the multi-guard positive (CW / CLOSING / LA / TW).
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing07NegSM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing07NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_07_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_07 (CLOSE-WAIT): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to a URG-only segment "
        "in CLOSE-WAIT; a conformant DUT stays silent";

    // Mirrors the positive's phase-1 seam (active OPEN + tester shutdown(WR) -> DUT CLOSE-WAIT),
    // with the fault armed AFTER the tester FIN (excluded only because it precedes the arm) and
    // BEFORE the URG inject so only the URG segment elicits the synthesized RST.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing07Phase1LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing07Phase1LocalOffset;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        const int tester_fd = open.listener.acceptOne();
        if (tester_fd < 0) return;
        ::shutdown(tester_fd, SHUT_WR);          // tester FIN -> DUT CLOSE-WAIT
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto seq_range = queryTcpSeqRange(tester_fd);
        if (seq_range.has_value()) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec urg{};
            urg.src_port = remote_port;
            urg.dst_port = local_port;
            urg.seq_num  = seq_range->snd_nxt;
            urg.ack_num  = 0U;
            urg.flags    = ::tc8::stimulus::kTcpFlagUrg;
            emitTcpFrame(cfg, iface, cfg.dut.mac, urg, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
        silentlyCloseTesterFd(tester_fd);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing07NegSM, tcp_flags_processing_07_neg)
