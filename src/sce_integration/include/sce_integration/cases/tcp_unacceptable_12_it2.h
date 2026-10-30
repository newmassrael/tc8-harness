#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_12_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_12_it2_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable12It2SM =
    ::SCE::Generated::tcp_unacceptable_12_it2::tcp_unacceptable_12_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable12It2SM>
    : TcpAnyBase<cases::TcpUnacceptable12It2SM> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_12_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_UNACCEPTABLE_12: a data segment with an unacceptable ACK number, "
        "sent to a DUT in LAST-ACK, is answered with an empty acknowledgement";

    static void stimulus(Captured &c, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable12Iteration(c, cfg, ctx, ::tc8::sce::tcp::kTcpUnacceptable12Phase2LocalOffset,
                                            cases::Unacceptable12Segment::kUnacceptableAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable12It2SM, tcp_unacceptable_12_it2)
