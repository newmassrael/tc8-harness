#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/tcp_mss_options_06.h"  // SSOT: positive runPhase + listen ports
#include "sce_integration/dut_control.h"

#include "tcp_mss_options_06_neg2_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions06Neg2SM = ::SCE::Generated::tcp_mss_options_06_neg2::tcp_mss_options_06_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.9 TCP_MSS_OPTIONS_06 phase 2: with an advertised MSS of 2000 (> the
// DUT MSS), a conformant DUT clamps the SEND segment to the DUT MSS of 1460 (RFC 1122 §4.2.2.6).
// kTcpFaultDataSegTruncate shrinks the DUT data segment's IP total_length so libtins re-slices the
// dissected payload to 64 B, so the phase2_segment_size_not_dut_mss_1460 fail-final (payload_len
// != 1460) is reachable. lwIP-only (kCapEgressFault). Twin of TCP_MSS_OPTIONS_06_NEG.
template <>
struct TestCaseTraits<cases::TcpMssOptions06Neg2SM>
    : TcpEgressFaultNegBase<cases::TcpMssOptions06Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_06_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_06 phase 2: the lwIP kTcpFaultDataSegTruncate egress "
        "flavor shrinks the DUT data segment below the 1460 B DUT MSS clamp; a conformant DUT "
        "segments at 1460 B";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        TesterAutoRstDrop rst_drop(cfg);
        (void)rst_drop;
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultDataSegTruncate);
        TestCaseTraits<cases::TcpMssOptions06SM>::runPhase(
            dut, cfg, iface,
            kTcpMssOptionsListenPort06b, kTcpMssOptionsTesterSrcPort06b,
            /*advertised_mss=*/2000U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions06Neg2SM, tcp_mss_options_06_neg2)
