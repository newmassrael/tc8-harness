#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/cases/_tcp_unacceptable_08_common.h"
#include "sce_integration/test_runner.h"

#include "tcp_unacceptable_08_it1_sm.h"

namespace tc8::sce::cases {

using TcpUnacceptable08It1SM =
    ::SCE::Generated::tcp_unacceptable_08_it1::tcp_unacceptable_08_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_UNACCEPTABLE_08",
    "A DUT in SYN-SENT answers a segment carrying an unacceptable ACK number (one with the "
    "flags SYN,ACK, one with ACK only) with a RST whose SEQ equals that ACK number "
    "(RFC 793 §3.4 p36 Establishing a Connection)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpUnacceptable08It1SM>
    : TcpAnyBase<cases::TcpUnacceptable08It1SM> {
    // The iteration leaves the DUT's active open in SYN-SENT (no tester listener) and injects
    // the unacceptable-ACK segment into that state. The testability CONNECT SP requires the
    // handshake to establish and so cannot hold a socket in SYN-SENT, while the opcode
    // non-blocking worker can — kCapTcpSynSentOpen makes the CLI capability gate honestly
    // SKIP this case on a testability backend instead of failing it. The DUT RST is observed
    // on pcap, so no state probe is required.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_UNACCEPTABLE_08_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_UNACCEPTABLE_08: a SYN,ACK segment with an unacceptable ACK number, "
        "sent to a DUT in SYN-SENT, is answered with a RST";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveUnacceptable08Iteration(
            ctx.dut, ctx.observer, cfg, ctx.iface,
            ::tc8::sce::tcp::kTcpUnacceptable08Phase1LocalOffset,
            static_cast<std::uint8_t>(::tc8::stimulus::kTcpFlagSyn | ::tc8::stimulus::kTcpFlagAck));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpUnacceptable08It1SM, tcp_unacceptable_08_it1)
