#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_06_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_invalid_06_it2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid06It2SM =
    ::SCE::Generated::tcp_flags_invalid_06_it2::tcp_flags_invalid_06_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid06It2SM>
    : TcpAnyBase<cases::TcpFlagsInvalid06It2SM> {
    // Same demand as iteration 1: the DUT's active open is left in SYN-SENT over the seam
    // (driveSeamSynSentOpen), which a testability backend cannot hold, and nothing more.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_INVALID_06_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_FLAGS_INVALID_06: an ACK carrying data with an acceptable ACK "
        "number, sent to a DUT in SYN-SENT, is dropped without a reply";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveFlagsInvalid06Iteration(cfg, ctx, ::tc8::sce::tcp::kTcpFlagsInvalid06Phase2LocalOffset,
                                            cases::FlagsInvalid06Probe::kWithData);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid06It2SM, tcp_flags_invalid_06_it2)
