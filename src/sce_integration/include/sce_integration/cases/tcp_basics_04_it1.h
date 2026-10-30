#pragma once

#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_basics_04_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_04_it1_sm.h"

namespace tc8::sce::cases {

using TcpBasics04It1SM = ::SCE::Generated::tcp_basics_04_it1::tcp_basics_04_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its three iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_BASICS_04",
    "A DUT whose TCP port is CLOSED answers a segment carrying neither RST nor ACK with an "
    "RST whose sequence number is zero (RFC 793 §3.9 p65 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04It1SM> : TcpAnyBase<cases::TcpBasics04It1SM> {
    static constexpr std::string_view kCaseId = "TCP_BASICS_04_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_BASICS_04: a bare SYN sent to a CLOSED port is answered with a "
        "RST whose SEQ is zero";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveBasics04Iteration(cfg, ctx, cases::Basics04Segment::kSyn);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04It1SM, tcp_basics_04_it1)
