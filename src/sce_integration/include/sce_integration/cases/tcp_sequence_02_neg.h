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
#include "sce_integration/dut_control.h"
#include "sce_integration/tcp_observation.h"
#include "sce_integration/test_runner.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_sequence_02_neg_sm.h"

namespace tc8::sce::cases {

using TcpSequence02NegSM =
    ::SCE::Generated::tcp_sequence_02_neg::tcp_sequence_02_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.17 TCP_SEQUENCE_02: kTcpFaultPureAckNumWrong flips the
// ack_num of the DUT's ACK to the injected SYN,ACK so it no longer equals tester ISN+1;
// a conformant DUT acks ISN+1. The DUT's own SYN is not a pure ACK, so the flavor is
// armed up front (arm-before) and corrupts only the single observed ACK. lwIP-only
// (kCapEgressFault). Mirrors tcp_sequence_02's SYN-SENT drive.
template <>
struct TestCaseTraits<cases::TcpSequence02NegSM>
    : TcpEgressFaultNegDrivenBase<cases::TcpSequence02NegSM> {
    // `driveSeamSynSentOpen` leaves the DUT in SYN-SENT WITHOUT establishing, which is
    // its own sub-interface — the base declares the TCP data plane and the fault seam,
    // not this one. Only 1 of that base's 15 users needs it, so it is declared here
    // rather than widened into the base. Extended from the base's value rather than
    // restated, so the two cannot drift (docs/tech-debt.md TD-22).
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        TcpEgressFaultNegDrivenBase<cases::TcpSequence02NegSM>::kRequiredCapabilities |
        ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId       = "TCP_SEQUENCE_02_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_SEQUENCE_02: the lwIP kTcpFaultPureAckNumWrong egress "
        "flavor flips the ack_num of the DUT's ACK; a conformant DUT acks the tester ISN+1";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);
        emitEgressFlavorArm(cfg, ctx.iface, ::tc8::ut::kTcpFaultPureAckNumWrong);

        const std::uint16_t local_port  =
            kBasicsActiveLocalPort + kTcpSequence02LocalOffset;
        const std::uint16_t remote_port =
            kBasicsActiveRemotePort + kTcpSequence02LocalOffset;

        TesterAutoRstDrop rst_drop(cfg);
        const ::tc8::sce::ObservationCursor armed = ctx.observer.mark();
        auto open = driveSeamSynSentOpen(ctx.dut, cfg, local_port, remote_port);

        const auto dut_syn = ctx.observer.awaitObservation(
            "dut_syn", armed, dutSynFrom(cfg.dut.ip, local_port),
            std::chrono::milliseconds(2000));
        if (!dut_syn) {
            if (open) ctx.dut.tcpControl()->closeTcp(open->socket);
            return;
        }
        const std::uint32_t dut_isn = segmentOf(dut_syn->view()).seq_num;

        ::tc8::stimulus::TcpSegmentSpec syn_ack{};
        syn_ack.src_port = remote_port;
        syn_ack.dst_port = local_port;
        syn_ack.seq_num  = kTesterInitialSeq;
        syn_ack.ack_num  = dut_isn + 1U;
        syn_ack.flags    = ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck;
        emitTcpFrame(cfg, ctx.iface, cfg.dut.mac, syn_ack,
                     /*initial_wait=*/std::chrono::milliseconds(0));

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (open) ctx.dut.tcpControl()->closeTcp(open->socket);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpSequence02NegSM, tcp_sequence_02_neg)
