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
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_processing_08_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08NegSM =
    ::SCE::Generated::tcp_flags_processing_08_neg::tcp_flags_processing_08_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.7 TCP_FLAGS_PROCESSING_08 phase 1 (CLOSED): a conformant DUT replies
// to a bare FIN on a closed port with RST seq=0 (RFC 793 §3.9). Unlike the ingress-synthesis P2/P3
// siblings, the conformant DUT genuinely emits this RST, so the fault is an EGRESS field
// corruption: kTcpFaultRstSeqWrong flips the DUT RST's sequence off zero. Pass = the non-zero
// sequence observed; fail_compliant = the DUT sent seq=0 despite the flavor (fault inert).
// lwIP-only (kCapEgressFault). Wire-identical to BASICS_04_NEG2 — a distinct sibling is required
// because fault_injection_coverage.json binds each fail-final to a _neg of its own base case.
template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08NegSM>
    : TcpEgressFaultNegBase<cases::TcpFlagsProcessing08NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_PROCESSING_08_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_PROCESSING_08 (CLOSED): the lwIP kTcpFaultRstSeqWrong "
        "egress flavor flips the closed-port RST sequence off zero; a conformant DUT sends seq=0";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagFin,
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08NegSM, tcp_flags_processing_08_neg)
