#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_mss_options_05_common.h"  // SSOT: the positive's drive
#include "sce_integration/dut_liveness.h"

#include "tcp_mss_options_05_neg2_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions05Neg2SM = ::SCE::Generated::tcp_mss_options_05_neg2::tcp_mss_options_05_neg2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of TCP_MSS_OPTIONS_05 iteration 2, the twin of the _NEG: the fault is armed
// between the two iterations, after the DUT answered the first liveness Echo, so only the
// answer to the second carries the wrong identifier. That makes the positive's
// `fail_dut_unresponsive_after_synack_with_ilen5_mss` reachable. An answer to the first Echo
// that is already wrong means the fault landed early, and the case is inconclusive.
template <>
struct TestCaseTraits<cases::TcpMssOptions05Neg2SM>
    : TcpAnyBase<cases::TcpMssOptions05Neg2SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_05_NEG2";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_MSS_OPTIONS_05 iteration 2: the lwIP kIcmpFaultEchoIdWrong "
        "egress flavor, armed after the first liveness Echo is answered, makes the answer to "
        "the second carry the wrong identifier; a conformant DUT answers with the probe's "
        "identifier";

    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen | ::tc8::sce::kCapEgressFault;
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::TcpAndIcmpv4;

    // The positive's drive, with the fault armed between the iterations.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::cases::mss_options_05::driveMssSynAckIterations(
            c, cfg, ctx,
            [] {},
            [&] { emitEgressFlavorArmMidStream(cfg, ctx.iface, ::tc8::ut::kIcmpFaultEchoIdWrong); });
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::liveness::raiseLivenessEchoReplies(c, sm, ev, Event::Dut_echo_reply,
                                                       Event::Dut_echo_reply_wrong_id);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions05Neg2SM, tcp_mss_options_05_neg2)
