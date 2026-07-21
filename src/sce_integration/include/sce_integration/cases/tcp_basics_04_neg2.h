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

#include "tcp_basics_04_neg2_sm.h"

namespace tc8::sce::cases {

using TcpBasics04Neg2SM = ::SCE::Generated::tcp_basics_04_neg2::tcp_basics_04_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04Neg2SM>
    : TcpEgressFaultNegBase<cases::TcpBasics04Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_04_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_BASICS_04 (FIN iteration): the lwIP kTcpFaultRstSeqWrong "
        "egress flavor flips the closed-port RST sequence off zero; a conformant DUT "
        "sends SEQ=0";

    // FIN-iteration sibling of tcp_basics_04_neg: arm the RST-seq fault, then raw-inject
    // one FIN (no ACK, no RST) to the closed port — the positive's second iteration. The
    // flavor flips the resulting DUT RST's seq off zero, proving the positive's
    // `dut_rst_seq_not_zero_after_fin` fail-final reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/::tc8::stimulus::kTcpFlagFin,
                        /*seq_num=*/kTesterInitialSeq + 0x100U,
                        /*ack_num=*/0U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04Neg2SM, tcp_basics_04_neg2)
