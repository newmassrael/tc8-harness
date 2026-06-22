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

#include "tcp_basics_05_neg2_sm.h"

namespace tc8::sce::cases {

using TcpBasics05Neg2SM = ::SCE::Generated::tcp_basics_05_neg2::tcp_basics_05_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics05Neg2SM>
    : TcpEgressFaultNegBase<cases::TcpBasics05Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_05_NEG2";
    static constexpr std::string_view kSpecSection  = "4.8.6.1";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_BASICS_05 (bare-ACK iteration): the lwIP kTcpFaultRstSeqWrong "
        "egress flavor flips the closed-port RST sequence off the incoming ACK; a conformant "
        "DUT sets SEQ = incoming.ACK";

    // Bare-ACK-iteration sibling of tcp_basics_05_neg: arm the RST-seq fault, then
    // raw-inject one bare ACK whose ACK is the positive's phase literal
    // (kTesterPilotAckPhaseAck) to the closed port. The flavor flips the resulting DUT
    // RST's seq, proving the positive's dut_rst_seq_not_ack_phase_ack_literal fail-final
    // reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagAck,
                        /*seq_num=*/kTesterInitialSeq + 0x100U,
                        /*ack_num=*/kTesterPilotAckPhaseAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics05Neg2SM, tcp_basics_05_neg2)
