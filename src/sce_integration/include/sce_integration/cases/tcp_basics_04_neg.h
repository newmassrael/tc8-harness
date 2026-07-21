#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_04_neg_sm.h"

namespace tc8::sce::cases {

using TcpBasics04NegSM = ::SCE::Generated::tcp_basics_04_neg::tcp_basics_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04NegSM>
    : TcpEgressFaultNegBase<cases::TcpBasics04NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_04_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_BASICS_04: the lwIP kTcpFaultRstSeqWrong egress flavor "
        "flips the closed-port RST sequence off zero; a conformant DUT sends SEQ=0";

    // Arm the RST-seq fault, then provoke a single closed-port RST the way the
    // positive's first iteration does — raw-inject one SYN to the closed port (no Upper
    // Tester setup needed; CLOSED is the default for an un-bound port). The flavor flips
    // the DUT RST's seq off zero (RST flag intact, so the case 4-tuple + RST conjuncts
    // still select it) — the injected violation the positive forbids. One iteration
    // suffices: the positive's three iterations (SYN/FIN/Data) all land on the identical
    // RFC 793 §3.9 seq==0 guard, so a single corrupted RST self-validates it.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagSyn,
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04NegSM, tcp_basics_04_neg)
