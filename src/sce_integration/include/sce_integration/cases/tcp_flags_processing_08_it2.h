#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_processing_08_common.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_seam_passive_open.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_processing_08_it2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsProcessing08It2SM =
    ::SCE::Generated::tcp_flags_processing_08_it2::tcp_flags_processing_08_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsProcessing08It2SM>
    : TcpAnyBase<cases::TcpFlagsProcessing08It2SM> {
    // Opens a passive listener over the Tier-2 seam (driveSeamListen), so it is not measurable
    // on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_PROCESSING_08_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_FLAGS_PROCESSING_08: a bare FIN sent to a DUT in LISTEN draws no "
        "response";

    // Passive listener, then a bare FIN from a tester port of its own. The DUT's LISTEN handler
    // drops a segment that is not a SYN (RFC 793 §3.9), so it stays silent; the SCXML absence
    // guard catches any DUT-emitted segment on the listen 4-tuple.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        using namespace ::tc8::sce::tcp;
        (void)driveSeamListen(ctx.dut, kTcpFlagsProcessing08ListenPort);
        cases::emitBareFin(cfg, ctx.iface, kTcpFlagsProcessing08ListenTesterPort,
                           kTcpFlagsProcessing08ListenPort);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsProcessing08It2SM, tcp_flags_processing_08_it2)
