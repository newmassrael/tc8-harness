#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_10_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_10_it1_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable10It1SM =
    ::SCE::Generated::tcp_unacceptable_10_it1::tcp_unacceptable_10_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_UNACCEPTABLE_10",
    "A DUT parked in FIN-WAIT-2 answers a data segment it cannot accept (out-of-window "
    "SEQ, or an ACK for bytes it never sent) with an empty acknowledgement carrying "
    "the right SEQ and ACK, and stays in FIN-WAIT-2 (RFC 793 §3.4)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable10It1SM>
    : TcpAnyBase<cases::TcpUnacceptable10It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen /
    // closeTcp), so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_10_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_UNACCEPTABLE_10: a data segment with an out-of-window SEQ, "
        "sent to a DUT in FIN-WAIT-2, is answered with an empty acknowledgement";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable10Iteration(ctx, cfg,
                                            ::tc8::sce::tcp::kTcpUnacceptable10Phase1LocalOffset,
                                            cases::Unacceptable10Segment::kOutOfWindowSeq);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable10It1SM, tcp_unacceptable_10_it1)
