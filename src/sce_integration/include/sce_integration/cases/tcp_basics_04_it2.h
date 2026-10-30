#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_basics_04_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_basics_04_it2_sm.h"

namespace tc8::sce::cases {

using TcpBasics04It2SM = ::SCE::Generated::tcp_basics_04_it2::tcp_basics_04_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpBasics04It2SM> : TcpAnyBase<cases::TcpBasics04It2SM> {
    static constexpr std::string_view kCaseId = "TCP_BASICS_04_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_BASICS_04: a bare FIN sent to a CLOSED port is answered with a "
        "RST whose SEQ is zero";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveBasics04Iteration(cfg, ctx, cases::Basics04Segment::kFin);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpBasics04It2SM, tcp_basics_04_it2)
