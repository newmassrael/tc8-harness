#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_08_neg3_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08Neg3SM =
    ::SCE::Generated::tcp_flags_processing_08_neg3::tcp_flags_processing_08_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_08 phase 3 (SYN-SENT): a conformant DUT in
// SYN-SENT silently drops a bare FIN (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP
// netif input hook synthesize the prohibited RST on the connection's 4-tuple when the FIN
// arrives, and the case passes only when that synthesized RST is observed. lwIP-only
// (kCapIngressFault). One of the three per-fail-final variants graduating the multi-guard
// positive.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08Neg3SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing08Neg3SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_08_NEG3";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_08 (SYN-SENT): the lwIP kTcpSynthRstOnDisruptive "
        "ingress flavor makes the DUT emit a RST to a bare FIN in SYN-SENT; a conformant DUT "
        "stays silent";

    // Mirrors the positive's phase-3 seam (active OPEN left in SYN-SENT + bare FIN inject), with
    // the fault armed after the DUT SYN observation and before the FIN inject.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing08LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing08LocalOffset;

        auto snippet = TcpFrameSnippet::forDutSyn(cfg, iface, local_port);

        (void)driveSeamSynSentOpen(dut, cfg, local_port, remote_port);

        const auto syn = snippet.tryCapture(std::chrono::milliseconds(500));
        if (!syn.has_value()) return;

        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec fin{};
        fin.src_port = remote_port;
        fin.dst_port = local_port;
        fin.seq_num  = kTesterInitialSeq;
        fin.ack_num  = 0U;
        fin.flags    = ::tc8::stimulus::kTcpFlagFin;
        emitTcpFrame(cfg, iface, cfg.dut.mac, fin, /*initial_wait=*/kFlavorArmSettle);
        std::this_thread::sleep_for(kSynthObserveHold);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08Neg3SM, tcp_flags_processing_08_neg3)
