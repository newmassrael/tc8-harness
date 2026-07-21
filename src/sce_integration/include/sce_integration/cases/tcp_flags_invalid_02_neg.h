#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_flags_invalid_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid02NegSM =
    ::SCE::Generated::tcp_flags_invalid_02_neg::tcp_flags_invalid_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.6 TCP_FLAGS_INVALID_02: kTcpFaultRstSeqWrong (reused, gated
// on the RST flag) flips the sequence number of the DUT's RST to the ACK-bearing LISTEN
// probe so it no longer equals SEG.ACK; a conformant DUT sets seq = SEG.ACK. Armed
// up front (the RST is the only RST in flight). The positive's phase-2 LISTEN-survival
// check is omitted — the _neg only proves the RST-seq guard reachable. lwIP-only
// (kCapEgressFault).
template <>
struct TestCaseTraits<cases::TcpFlagsInvalid02NegSM>
    : TcpEgressFaultNegBase<cases::TcpFlagsInvalid02NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_FLAGS_INVALID_02_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_FLAGS_INVALID_02: the lwIP kTcpFaultRstSeqWrong egress "
        "flavor flips the LISTEN RST's seq off SEG.ACK; a conformant DUT sets seq = SEG.ACK";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kTcpFaultRstSeqWrong);

        const auto listen = driveSeamListen(dut, kBasicsListenPort);
        if (!listen) {
            return;
        }
        ::tc8::stimulus::TcpSegmentSpec syn_ack{};
        syn_ack.src_port = kBasicsTesterPort;
        syn_ack.dst_port = kBasicsListenPort;
        syn_ack.seq_num  = kTesterInitialSeq;
        syn_ack.ack_num  = kFlagsInvalid02ProbeAck;
        syn_ack.flags    = ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, iface, cfg.dut.mac, syn_ack);
        std::this_thread::sleep_for(kTcpPilotPhaseGap);

        dut.tcpControl()->closeTcp(*listen);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid02NegSM, tcp_flags_invalid_02_neg)
