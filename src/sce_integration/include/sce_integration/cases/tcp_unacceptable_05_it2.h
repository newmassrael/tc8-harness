#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_05_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_05_it2_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable05It2SM =
    ::SCE::Generated::tcp_unacceptable_05_it2::tcp_unacceptable_05_it2;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable05It2SM>
    : TcpAnyBase<cases::TcpUnacceptable05It2SM> {
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_05_IT2";
    static constexpr std::string_view kDescription =
        "Iteration 2 of TCP_UNACCEPTABLE_05: a bare ACK with an arbitrary ACK number, sent to "
        "a DUT in LISTEN, is answered with an RST";

    static constexpr std::uint16_t kListenPort = 12346U;

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable05Iteration(cfg, ctx, kListenPort,
                                            ::tc8::stimulus::kTcpFlagAck,
                                            ::tc8::sce::tcp::kTesterInitialSeq + 0x100U);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable05It2SM, tcp_unacceptable_05_it2)
