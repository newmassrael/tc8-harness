#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_iteration.h"
#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_flags_invalid_06_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/test_runner.h"

#include "tcp_flags_invalid_06_it1_sm.h"

namespace tc8::sce::cases {

using TcpFlagsInvalid06It1SM =
    ::SCE::Generated::tcp_flags_invalid_06_it1::tcp_flags_invalid_06_it1;

}  // namespace tc8::sce::cases

// The TC8 case is the ordered set of its two iterations (case_iteration.h); declared here,
// once, beside the first.
TC8_REGISTER_ITERATED_CASE(
    "TCP_FLAGS_INVALID_06",
    "A DUT parked in SYN-SENT drops a segment that carries neither SYN nor RST, even when "
    "its ACK number is acceptable, without answering it, and stays in SYN-SENT, whether the "
    "segment carries data or not (RFC 793 §3.9 p68 Event Processing)")

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpFlagsInvalid06It1SM>
    : TcpAnyBase<cases::TcpFlagsInvalid06It1SM> {
    // The iteration leaves the DUT's active open in SYN-SENT (no tester listener) and
    // injects the bare-ACK probe into that state. The testability CONNECT SP requires the
    // handshake to establish and so cannot hold a socket in SYN-SENT, while the opcode
    // non-blocking worker can — kCapTcpSynSentOpen makes the CLI capability gate honestly
    // SKIP this case on a testability backend (Tier 2 2b#4) instead of failing it. No state
    // probe is needed: the DUT SYN is observed on pcap and the verdict is the SCXML absence
    // window.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    static constexpr std::string_view kCaseId = "TCP_FLAGS_INVALID_06_IT1";
    static constexpr std::string_view kDescription =
        "Iteration 1 of TCP_FLAGS_INVALID_06: a bare ACK with an acceptable ACK number, sent "
        "to a DUT in SYN-SENT, is dropped without a reply";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig &cfg,
                         ::tc8::sce::StimulusContext &ctx) {
        cases::driveFlagsInvalid06Iteration(cfg, ctx, ::tc8::sce::tcp::kTcpFlagsInvalid06Phase1LocalOffset,
                                            cases::FlagsInvalid06Probe::kNoData);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpFlagsInvalid06It1SM, tcp_flags_invalid_06_it1)
