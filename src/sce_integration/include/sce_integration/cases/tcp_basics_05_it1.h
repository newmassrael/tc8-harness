#pragma once

#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_basics_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_05_it1_sm.h"

namespace tc8::sce::cases {

using TcpBasics05It1SM = ::SCE::Generated::tcp_basics_05_it1::tcp_basics_05_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_BASICS_05",
    "A DUT whose TCP port is CLOSED answers a segment carrying ACK and not RST with an RST "
    "whose sequence number is that segment's ACK number (RFC 793 §3.9 p65 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics05It1SM> : TcpAnyBase<cases::TcpBasics05It1SM> {
    static constexpr std::string_view kCaseId = "TCP_BASICS_05_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_BASICS_05: a SYN,ACK sent to a CLOSED port is answered with a RST "
        "whose SEQ is the incoming ACK";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveBasics05Iteration(cfg, ctx, cases::Basics05Segment::kSynAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics05It1SM, tcp_basics_05_it1)
