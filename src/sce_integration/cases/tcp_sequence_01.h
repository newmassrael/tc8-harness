#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_sequence_01_sm.h"

namespace tc8::sce::cases {

using TcpSequence01SM =
    ::SCE::Generated::tcp_sequence_01::tcp_sequence_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpSequence01SM>
    : TcpAnyBase<cases::TcpSequence01SM> {
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_01";
    static constexpr std::string_view kSpecSection  = "4.8.6.17";
    static constexpr std::string_view kDescription  =
        "DUT acknowledges tester ISN by emitting SYN,ACK with "
        "ack_num == tester_seq + 1 (RFC 793 §3.1).";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        // Seam raw-passive ACCEPT: DUT LISTEN, tester injects a SYN with
        // ISN = kTesterInitialSeq, the 3-way completes, and the accepted
        // connection comes back. The pass guard is purely the DUT SYN+ACK
        // ack_num (== tester_isn + 1), captured by the SCXML during the
        // handshake — so this runs and PASSes on either backend.
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

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:               return "pass";
            case State::Fail_wrong_ack_num: return "fail:dut_synack_ack_num_does_not_acknowledge_tester_isn";
            case State::Fail_timeout:       return "fail:no_dut_syn_ack_within_listen_window";
            default:                        return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence01SM, tcp_sequence_01)
