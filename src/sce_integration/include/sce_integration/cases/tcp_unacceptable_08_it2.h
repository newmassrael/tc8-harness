#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_08_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_08_it2_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable08It2SM =
    ::SCE::Generated::tcp_unacceptable_08_it2::tcp_unacceptable_08_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable08It2SM>
    : TcpAnyBase<cases::TcpUnacceptable08It2SM> {
    // Same demand as the first iteration: a SYN-SENT open held with no tester listener, which
    // only the opcode backend can do (see kCapTcpSynSentOpen).
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_08_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_UNACCEPTABLE_08: an ACK-only segment with an unacceptable ACK number, "
        "sent to a DUT in SYN-SENT, is answered with a RST";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable08Iteration(ctx.dut, ctx.observer, cfg, ctx.iface,
                                            ::tc8::sce::tcp::kTcpUnacceptable08Phase2LocalOffset,
                                            ::tc8::stimulus::kTcpFlagAck);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable08It2SM, tcp_unacceptable_08_it2)
