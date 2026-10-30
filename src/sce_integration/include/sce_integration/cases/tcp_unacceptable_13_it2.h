#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_13_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_13_it2_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable13It2SM =
    ::SCE::Generated::tcp_unacceptable_13_it2::tcp_unacceptable_13_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable13It2SM>
    : TcpDutDrivenBase<cases::TcpUnacceptable13It2SM> {
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_13_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_UNACCEPTABLE_13: a data segment with an unacceptable ACK number, "
        "sent to a DUT in TIME-WAIT, is answered with an acknowledgement";

    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable13Iteration(c, cfg, ctx, ::tc8::sce::tcp::kTcpUnacceptable13Phase2LocalOffset,
                                            cases::Unacceptable13Segment::kUnacceptableAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable13It2SM, tcp_unacceptable_13_it2)
