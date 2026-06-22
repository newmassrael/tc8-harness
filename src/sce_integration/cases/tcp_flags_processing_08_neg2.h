#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_08_neg2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08Neg2SM =
    ::SCE::Generated::tcp_flags_processing_08_neg2::tcp_flags_processing_08_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_08 phase 2 (LISTEN): a conformant DUT in
// LISTEN silently drops a bare FIN (RFC 793 §3.9). kTcpSynthRstOnDisruptive makes the lwIP netif
// input hook synthesize the prohibited RST on the listen 4-tuple when the FIN arrives, and the
// case passes only when that synthesized RST is observed. lwIP-only (kCapIngressFault). One of
// the three per-fail-final variants graduating the multi-guard positive.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08Neg2SM>
    : TcpIngressFaultNegBase<cases::TcpFlagsProcessing08Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_08_NEG2";
    static constexpr std::string_view kSpecSection  = "4.8.6.7";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_08 (LISTEN): the lwIP kTcpSynthRstOnDisruptive "
        "ingress flavor makes the DUT emit a RST to a bare FIN in LISTEN; a conformant DUT stays "
        "silent";

    // Mirrors the positive's phase-2 seam (passive LISTEN + bare FIN inject), with the fault
    // armed before the FIN. A passive LISTEN emits nothing to precondition on, so the arm runs
    // right after the listen open.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        constexpr std::uint16_t kListenPort = kBasicsListenPort + 14U;
        constexpr std::uint16_t kTesterPort = kBasicsTesterPort + 71U;

        (void)driveSeamListen(dut, kListenPort);

        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthRstOnDisruptive);

        ::tc8::stimulus::TcpSegmentSpec fin{};
        fin.src_port = kTesterPort;
        fin.dst_port = kListenPort;
        fin.seq_num  = kTesterInitialSeq;
        fin.ack_num  = 0U;
        fin.flags    = ::tc8::stimulus::kTcpFlagFin;
        emitTcpFrame(cfg, iface, cfg.dut.mac, fin, /*initial_wait=*/kFlavorArmSettle);
        std::this_thread::sleep_for(kSynthRstObserveHold);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08Neg2SM, tcp_flags_processing_08_neg2)
