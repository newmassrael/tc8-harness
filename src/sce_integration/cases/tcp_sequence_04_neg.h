#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_sequence_04_neg_sm.h"

namespace tc8::sce::cases {

using TcpSequence04NegSM =
    ::SCE::Generated::tcp_sequence_04_neg::tcp_sequence_04_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.17 TCP_SEQUENCE_04: kTcpFaultSynAckAckWrong flips the
// passive-open SYN,ACK's ack_num so it no longer equals tester ISN+1 (=0, tester ISN
// 0xFFFFFFFF wraps); a conformant DUT acks 0. The tester completes the handshake from
// the uncorrupted seq, so the SYN,ACK is captured. lwIP-only (kCapEgressFault). Same
// flavor + raw passive accept as tcp_sequence_01_neg, with the wrap-around tester ISN.
template <>
struct TestCaseTraits<cases::TcpSequence04NegSM>
    : TcpEgressFaultNegBase<cases::TcpSequence04NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_04_NEG";
    static constexpr std::string_view kSpecSection  = "4.8.6.17";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_SEQUENCE_04: the lwIP kTcpFaultSynAckAckWrong egress "
        "flavor flips the SYN,ACK ack_num; a conformant DUT acks the wrapped tester ISN + 1";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultSynAckAckWrong);

        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpSequence04ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence04TesterSrcPort,
            /*tester_isn=*/0xFFFFFFFFU);

        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence04NegSM, tcp_sequence_04_neg)
