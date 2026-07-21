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

#include "tcp_mss_options_06_neg_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions06NegSM = ::SCE::Generated::tcp_mss_options_06_neg::tcp_mss_options_06_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.9 TCP_MSS_OPTIONS_06 phase 1: with an advertised MSS of 200 (< the
// DUT MSS), a conformant DUT segments a SEND at 200 B (RFC 1122 §4.2.2.6). kTcpFaultDataSegTruncate
// shrinks the DUT data segment's IP total_length so libtins re-slices the dissected payload to 64 B,
// so the phase1_segment_size_not_advertised_mss_200 fail-final (payload_len != 200) is reachable.
// lwIP-only (kCapEgressFault). Reuses the positive's runPhase (SSOT) so the drive cannot drift; the
// CASE 2 (MSS 2000 -> 1460) twin is the _NEG2.
template <>
struct TestCaseTraits<cases::TcpMssOptions06NegSM>
    : TcpEgressFaultNegBase<cases::TcpMssOptions06NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_06_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_06 phase 1: the lwIP kTcpFaultDataSegTruncate egress "
        "flavor shrinks the DUT data segment below the advertised 200 B MSS; a conformant DUT "
        "segments at 200 B";

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
            kTcpMssOptionsListenPort06a, kTcpMssOptionsTesterSrcPort06a,
            /*advertised_mss=*/200U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions06NegSM, tcp_mss_options_06_neg)
