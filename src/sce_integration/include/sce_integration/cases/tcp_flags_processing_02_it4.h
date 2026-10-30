#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_02_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_02_it4_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing02It4SM =
    ::SCE::Generated::tcp_flags_processing_02_it4::tcp_flags_processing_02_it4;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing02It4SM>
    : TcpAnyBase<cases::TcpFlagsProcessing02It4SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamActiveOpen / closeTcp),
    // so it is not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_02_IT4";
    static constexpr std::string_view kDescription =
        "Iteration 4 of TCP_FLAGS_PROCESSING_02: a DUT in FIN-WAIT-2, hit by an in-window "
        "RST, answers a following ACK on that 4-tuple with an RST";

    // No AckDrop: the tester kernel auto-ACK advances the DUT FIN-WAIT-1 -> FIN-WAIT-2; no
    // shutdown(WR) follows.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        cases::driveFlagsProcessing02Connected(
            cfg, ctx, ::tc8::sce::tcp::kTcpFlagsProcessing02Phase3LocalOffset,
            cases::FlagsProcessing02State::kFinWait2);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing02It4SM, tcp_flags_processing_02_it4)
