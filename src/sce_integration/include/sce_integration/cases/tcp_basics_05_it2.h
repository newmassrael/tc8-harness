#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_basics_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_05_it2_sm.h"

namespace tc8::sce::cases {

using TcpBasics05It2SM = ::SCE::Generated::tcp_basics_05_it2::tcp_basics_05_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics05It2SM> : TcpAnyBase<cases::TcpBasics05It2SM> {
    static constexpr std::string_view kCaseId = "TCP_BASICS_05_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_BASICS_05: a bare ACK sent to a CLOSED port is answered with a RST "
        "whose SEQ is the incoming ACK";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveBasics05Iteration(cfg, ctx, cases::Basics05Segment::kAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics05It2SM, tcp_basics_05_it2)
