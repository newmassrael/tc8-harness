#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_05_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing05It1SM =
    ::SCE::Generated::tcp_flags_processing_05_it1::tcp_flags_processing_05_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_PROCESSING_05",
    "A DUT whose connection is in SYN-RCVD returns to LISTEN on an in-window SYN or an "
    "in-window SYN+ACK; a fresh SYN from another tester port drawing a DUT SYN+ACK is the "
    "wire-observable proof (RFC 1122 §4.2.2.20(e) p94)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing05It1SM>
    : TcpAnyBase<cases::TcpFlagsProcessing05It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamListen), so it is not
    // measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_05_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_PROCESSING_05: a DUT with a half-open connection in "
        "SYN-RCVD, hit by an in-window SYN, still answers a fresh SYN from another tester "
        "port with a SYN+ACK";

    // The DUT is put into LISTEN through the listen-only seam verb and verdicts on its wire
    // response to a tester SYN, an in-window SYN on that half-open connection, and a verify
    // SYN from a different tester port. The tester-side raw injects and the auto-RST
    // suppression stay case-owned.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        cases::driveFlagsProcessing05(cfg, ctx, cases::kFlagsProcessing05SynPorts,
                                      cases::FlagsProcessing05Inject::kSyn);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing05It1SM, tcp_flags_processing_05_it1)
