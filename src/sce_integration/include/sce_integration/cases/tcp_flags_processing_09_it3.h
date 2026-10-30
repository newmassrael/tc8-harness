#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_09_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_09_it3_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing09It3SM =
    ::SCE::Generated::tcp_flags_processing_09_it3::tcp_flags_processing_09_it3;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing09It3SM>
    : TcpAnyBase<cases::TcpFlagsProcessing09It3SM> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_09_IT3";
    static constexpr std::string_view kDescription =
        "Iteration 3 of TCP_FLAGS_PROCESSING_09: a duplicate FIN,ACK with an ACK number that "
        "does not acknowledge the DUT's FIN leaves a DUT in LAST-ACK where it was";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveProcessing09Iteration(ctx.dut, cfg, ctx.iface,
                                          ::tc8::sce::tcp::kTcpFlagsProcessing09Phase3LocalOffset,
                                          cases::Processing09State::kLastAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing09It3SM, tcp_flags_processing_09_it3)
