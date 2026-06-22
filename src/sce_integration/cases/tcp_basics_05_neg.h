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

#include "tcp_basics_05_neg_sm.h"

namespace tc8::sce::cases {

using TcpBasics05NegSM = ::SCE::Generated::tcp_basics_05_neg::tcp_basics_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics05NegSM>
    : TcpEgressFaultNegBase<cases::TcpBasics05NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_05_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_BASICS_05 (SYN,ACK iteration): the lwIP kTcpFaultRstSeqWrong "
        "egress flavor flips the closed-port RST sequence off the incoming ACK; a conformant "
        "DUT sets SEQ = incoming.ACK";

    // SYN,ACK-iteration sibling: arm the RST-seq fault, then raw-inject one SYN,ACK whose
    // ACK is the positive's phase literal (0xC0FFEE00) to the closed port. A conformant DUT
    // replies RST with SEQ = that ACK; the flavor flips it (RST flag intact), proving the
    // positive's dut_rst_seq_not_synack_ack_literal fail-final reachable. The literal is
    // duplicated from tcp_basics_05.h rather than included (its TC8_REGISTER_CASE must not
    // be pulled into this TU); it matches the _neg scxml guard.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/static_cast<std::uint8_t>(
                            ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck),
                        /*seq_num=*/kTesterInitialSeq,
                        /*ack_num=*/0xC0FFEE00U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics05NegSM, tcp_basics_05_neg)
