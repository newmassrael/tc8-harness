#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_invalid_05_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid05It1SM =
    ::SCE::Generated::tcp_flags_invalid_05_it1::tcp_flags_invalid_05_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_INVALID_05",
    "A DUT in SYN-SENT moves to CLOSED on an RST that carries an acceptable ACK, whether the "
    "segment also carries SYN or not (RFC 793 §3.9 p67 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid05It1SM>
    : TcpAnyBase<cases::TcpFlagsInvalid05It1SM> {
    // The iteration leaves the DUT's active open in SYN-SENT (no tester listener). The
    // testability CONNECT SP requires the handshake to establish and so cannot hold a socket in
    // SYN-SENT, while the opcode non-blocking worker can; kCapTcpSynSentOpen makes the CLI
    // capability gate honestly SKIP this case on a testability backend instead of failing it.
    // No state probe is needed: the DUT SYN is observed on pcap and the verdict is the SCXML
    // absence window.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_INVALID_05_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_INVALID_05: a DUT in SYN-SENT receives SYN,ACK,RST with an "
        "acceptable ACK and moves to CLOSED, so its SYN retransmit stops";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveFlagsInvalid05Iteration(
            ctx.dut, ctx.observer, cfg, ctx.iface,
            ::tc8::sce::tcp::kTcpFlagsInvalid05Phase1LocalOffset,
            static_cast<std::uint8_t>(::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck |
                                      ::tc8::stimulus::kTcpFlagRst));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid05It1SM, tcp_flags_invalid_05_it1)
