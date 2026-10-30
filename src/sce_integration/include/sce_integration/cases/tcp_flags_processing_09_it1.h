#pragma once

#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_09_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_09_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09It1SM =
    ::SCE::Generated::tcp_flags_processing_09_it1::tcp_flags_processing_09_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its three iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_PROCESSING_09",
    "A DUT in CLOSE-WAIT, CLOSING or LAST-ACK keeps its state when it receives a duplicate "
    "FIN that carries the ACK flag (RFC 793 §3.9 p75 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09It1SM>
    : TcpAnyBase<cases::TcpFlagsProcessing09It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen), so it is not
    // measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_09_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_PROCESSING_09: a duplicate FIN,ACK with a valid ACK number "
        "leaves a DUT in CLOSE-WAIT where it was";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveProcessing09Iteration(ctx.dut, cfg, ctx.iface,
                                          ::tc8::sce::tcp::kTcpFlagsProcessing09Phase1LocalOffset,
                                          cases::Processing09State::kCloseWait);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09It1SM, tcp_flags_processing_09_it1)
