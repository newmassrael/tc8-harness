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

#include "tcp_sequence_01_neg_sm.h"

namespace tc8::sce::cases {

using TcpSequence01NegSM =
    ::SCE::Generated::tcp_sequence_01_neg::tcp_sequence_01_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence01NegSM>
    : TcpEgressFaultNegBase<cases::TcpSequence01NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_01_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_SEQUENCE_01: the lwIP kTcpFaultSynAckAckWrong egress "
        "flavor flips the SYN,ACK ack_num; a conformant DUT acks the tester ISN + 1";

    // Arm the SYN,ACK ack-number fault, then drive the same raw-passive accept the
    // positive uses. The flavor flips the DUT SYN,ACK ack_num (flags stay SYN+ACK);
    // the tester completes the handshake from the uncorrupted seq, so the SYN,ACK is
    // captured with a wrong ack_num — the injected violation the positive forbids.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultSynAckAckWrong);

        auto open = driveSeamRawPassiveAccept(
            dut, cfg, iface,
            kTcpSequence01ListenPort,
            std::vector<std::uint8_t>{},
            kTcpSequence01TesterSrcPort,
            /*tester_isn=*/kTesterInitialSeq);

        if (open.conn) {
            ::tc8::sce::seamTcpControl(dut).closeTcp(open.conn->socket);
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence01NegSM, tcp_sequence_01_neg)
