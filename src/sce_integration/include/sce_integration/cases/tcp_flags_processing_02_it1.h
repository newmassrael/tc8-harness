#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_02_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_02_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing02It1SM =
    ::SCE::Generated::tcp_flags_processing_02_it1::tcp_flags_processing_02_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its five iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_PROCESSING_02",
    "A DUT whose connection is in SYN-RCVD, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 or "
    "CLOSE-WAIT returns to CLOSED on an in-window RST; a verify-probe ACK on the same "
    "4-tuple then draws a DUT RST as the wire-observable proof (RFC 793 §3.9 p70)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing02It1SM>
    : TcpAnyBase<cases::TcpFlagsProcessing02It1SM> {
    // Drives the DUT's TCP data plane over the Tier-2 seam (driveSeamListen), so it is not
    // measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_02_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_PROCESSING_02: a DUT with a half-open connection in "
        "SYN-RCVD, hit by an in-window RST, answers a following ACK on that 4-tuple with an RST";

    // The DUT is put into LISTEN through the listen-only seam verb and verdicts on its wire
    // response to a tester SYN that the spec RST then kills (SYN-RCVD never completes an
    // accept, so there is no handle to close). The tester-side raw RST / verify-ACK injects,
    // RstDrop and silent dispose stay case-owned.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        cases::driveFlagsProcessing02SynRcvd(cfg, ctx);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing02It1SM, tcp_flags_processing_02_it1)
