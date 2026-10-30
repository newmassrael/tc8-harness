#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_invalid_05_it2_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05It2SM =
    ::SCE::Generated::tcp_flags_invalid_05_it2::tcp_flags_invalid_05_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05It2SM>
    : TcpAnyBase<cases::TcpFlagsInvalid05It2SM> {
    // Holds the DUT in SYN-SENT like iteration 1, so it needs the same two capabilities.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_INVALID_05_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_FLAGS_INVALID_05: a DUT in SYN-SENT receives ACK,RST with an "
        "acceptable ACK and moves to CLOSED, so its SYN retransmit stops";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveFlagsInvalid05Iteration(
            ctx.dut, ctx.observer, cfg, ctx.iface,
            ::tc8::sce::tcp::kTcpFlagsInvalid05Phase2LocalOffset,
            static_cast<std::uint8_t>(::tc8::stimulus::kTcpFlagAck | ::tc8::stimulus::kTcpFlagRst));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05It2SM, tcp_flags_invalid_05_it2)
