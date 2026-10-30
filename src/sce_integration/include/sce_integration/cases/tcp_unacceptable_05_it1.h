#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_05_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_05_it1_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable05It1SM =
    ::SCE::Generated::tcp_unacceptable_05_it1::tcp_unacceptable_05_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_UNACCEPTABLE_05",
    "A DUT in LISTEN answers a segment carrying an unacceptable ACK (SYN+ACK, then a bare "
    "ACK) with an RST, and stays in LISTEN (RFC 793 §3.4 p36 Establishing a Connection)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable05It1SM>
    : TcpAnyBase<cases::TcpUnacceptable05It1SM> {
    // Drives the DUT into LISTEN over the Tier-2 seam (driveSeamListen / closeTcp), so it is
    // not measurable on a backend without ITcpControl.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_05_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_UNACCEPTABLE_05: a SYN+ACK with an arbitrary ACK number, sent to "
        "a DUT in LISTEN, is answered with an RST";

    static constexpr std::uint16_t kListenPort = 12345U;

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable05Iteration(
            cfg, ctx, kListenPort,
            ::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck,
            ::tc8::sce::tcp::kTesterInitialSeq);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable05It1SM, tcp_unacceptable_05_it1)
