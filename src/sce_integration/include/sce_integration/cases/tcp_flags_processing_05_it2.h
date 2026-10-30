#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_05_it2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing05It2SM =
    ::SCE::Generated::tcp_flags_processing_05_it2::tcp_flags_processing_05_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing05It2SM>
    : TcpAnyBase<cases::TcpFlagsProcessing05It2SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamListen), so it is not
    // measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_05_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_FLAGS_PROCESSING_05: a DUT with a half-open connection in "
        "SYN-RCVD, hit by an in-window SYN+ACK, still answers a fresh SYN from another "
        "tester port with a SYN+ACK";

    // As the first iteration, with a SYN+ACK that acknowledges the DUT's initial sequence
    // number as the injected segment.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        cases::driveFlagsProcessing05(cfg, ctx, cases::kFlagsProcessing05SynAckPorts,
                                      cases::FlagsProcessing05Inject::kSynAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing05It2SM, tcp_flags_processing_05_it2)
