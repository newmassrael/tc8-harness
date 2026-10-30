#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_13_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_13_it1_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable13It1SM =
    ::SCE::Generated::tcp_unacceptable_13_it1::tcp_unacceptable_13_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_UNACCEPTABLE_13",
    "A DUT parked in TIME-WAIT answers a data segment it cannot accept (out-of-window "
    "SEQ, or an ACK for bytes it never sent) with an acknowledgement carrying the right "
    "SEQ and ACK, and stays in TIME-WAIT (RFC 793 §3.4)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable13It1SM>
    : TcpDutDrivenBase<cases::TcpUnacceptable13It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamTimeWaitFw2: active
    // OPEN and closeTcp), so TcpDutDrivenBase's kCapTcpControl is the whole requirement: the
    // case is not measurable on a backend without ITcpControl. The raw-injected probe
    // needs nothing from the DUT.
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_13_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_UNACCEPTABLE_13: a data segment with an out-of-window SEQ, "
        "sent to a DUT in TIME-WAIT, is answered with an acknowledgement";

    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable13Iteration(c, cfg, ctx, ::tc8::sce::tcp::kTcpUnacceptable13Phase1LocalOffset,
                                            cases::Unacceptable13Segment::kOutOfWindowSeq);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable13It1SM, tcp_unacceptable_13_it1)
