#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_basics_04_neg3_sm.h"

namespace tc8::sce::cases {

using TcpBasics04Neg3SM = ::SCE::Generated::tcp_basics_04_neg3::tcp_basics_04_neg3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04Neg3SM>
    : TcpEgressFaultNegBase<cases::TcpBasics04Neg3SM> {
    static constexpr std::string_view kCaseId       = "TCP_BASICS_04_NEG3";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_BASICS_04 (Data iteration): the lwIP kTcpFaultRstSeqWrong "
        "egress flavor flips the closed-port RST sequence off zero; a conformant DUT "
        "sends SEQ=0";

    // Same fixed body the positive's third iteration sends — a "Data segment" (no ACK,
    // no RST) carrying payload; opaque to the spec (the assertion is on the RST seq).
    static constexpr std::array<std::uint8_t, 4> kIter3DataPayload = {
        0xAAU, 0xBBU, 0xCCU, 0xDDU};

    // Data-iteration sibling of tcp_basics_04_neg: arm the RST-seq fault, then raw-inject
    // one no-flag Data segment to the closed port — the positive's third iteration. The
    // flavor flips the resulting DUT RST's seq off zero, proving the positive's
    // `dut_rst_seq_not_zero_after_data` fail-final reachable.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        emitTcpStimulus(cfg, iface, cfg.dut.mac,
                        /*dst_port=*/kBasicsClosedPort,
                        /*flags=*/0U,
                        /*seq_num=*/kTesterInitialSeq + 0x200U,
                        /*ack_num=*/0U,
                        /*payload=*/std::vector<std::uint8_t>(
                            kIter3DataPayload.begin(), kIter3DataPayload.end()));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04Neg3SM, tcp_basics_04_neg3)
