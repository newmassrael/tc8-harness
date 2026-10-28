#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_mss_options_05_common.h"  // SSOT: the positive's drive
#include "sce_integration/dut_liveness.h"

#include "tcp_mss_options_05_neg_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions05NegSM = ::SCE::Generated::tcp_mss_options_05_neg::tcp_mss_options_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of TCP_MSS_OPTIONS_05 iteration 1: the positive fails the DUT when the
// liveness Echo sent after the ilen=0 SYN,ACK goes unanswered. The lwIP fixture cannot drop an
// Echo Reply, but kIcmpFaultEchoIdWrong flips its identifier, and a reply that does not carry
// the probe's identifier is no answer to the probe. Armed before iteration 1, the fault makes
// the positive's `fail_dut_unresponsive_after_synack_with_ilen0_mss` reachable, and this case
// passes when that wrong-identifier reply is observed. lwIP-only (kCapEgressFault); the
// kernel-backed DUT has no fixture seam. The iteration 2 twin is the _NEG2.
template <>
struct TestCaseTraits<cases::TcpMssOptions05NegSM>
    : TcpAnyBase<cases::TcpMssOptions05NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_05_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_05 iteration 1: the lwIP kIcmpFaultEchoIdWrong "
        "egress flavor makes the DUT's answer to the liveness Echo carry the wrong identifier; "
        "a conformant DUT answers with the probe's identifier";

    // The positive's own requirements (it drives the DUT over the seam and holds a SYN-SENT
    // open) plus the fixture's egress fault.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen | ::tc8::sce::kCapEgressFault;
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::TcpAndIcmpv4;

    // The positive's drive, with the fault armed before iteration 1.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::cases::mss_options_05::driveMssSynAckIterations(
            c, cfg, ctx,
            [&] { emitEgressFlavorArm(cfg, ctx.iface, ::tc8::ut::kIcmpFaultEchoIdWrong); },
            [] {});
    }

    // The right-identifier reply (the fault was inert) and the wrong-identifier reply (the
    // fault landed) are told apart; the case's own TCP segments bear on no transition.
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::liveness::raiseLivenessEchoReplies(c, sm, ev, Event::Dut_echo_reply,
                                                       Event::Dut_echo_reply_wrong_id);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions05NegSM, tcp_mss_options_05_neg)
