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

#include "tcp_flags_processing_07_neg4_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing07Neg4SM =
    ::SCE::Generated::tcp_flags_processing_07_neg4::tcp_flags_processing_07_neg4;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_07 phase 4 (TIME-WAIT): a conformant DUT in
// TIME-WAIT silently ignores a URG-only segment (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes
// the lwIP netif input hook synthesize the prohibited RST on the connection's 4-tuple when the
// URG-only segment arrives, and the case passes only when that synthesized RST is observed.
// lwIP-only (kCapIngressFault). One of the four per-fail-final variants graduating the
// multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing07Neg4SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing07Neg4SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_07_NEG4";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_07 (TIME-WAIT): the lwIP "
        "kTcpSynthRstOnDisruptive ingress flavor makes the DUT emit a RST to a URG-only segment "
        "in TIME-WAIT; a conformant DUT stays silent";

    // Mirrors the positive's phase-4 seam (FIN-WAIT-2 TIME-WAIT prelude -> DUT TIME-WAIT;
    // driveSeamTimeWaitFw2 closes the tester fd internally), with the fault armed AFTER the
    // prelude's FINs and BEFORE the URG inject.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + kTcpFlagsProcessing07Phase4LocalOffset;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + kTcpFlagsProcessing07Phase4LocalOffset;

        const auto info = driveSeamTimeWaitFw2(dut, cfg, local_port, remote_port);
        if (info.ok) {
            emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);
            ::tc8::stimulus::TcpSegmentSpec urg{};
            urg.src_port = remote_port;
            urg.dst_port = local_port;
            urg.seq_num  = info.tester_seq_post_fin;
            urg.ack_num  = 0U;
            urg.flags    = ::tc8::stimulus::kTcpFlagUrg;
            emitTcpFrame(cfg, iface, cfg.dut.mac, urg, /*initial_wait=*/kFlavorArmSettle);
            std::this_thread::sleep_for(kSynthRstObserveHold);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing07Neg4SM, tcp_flags_processing_07_neg4)
