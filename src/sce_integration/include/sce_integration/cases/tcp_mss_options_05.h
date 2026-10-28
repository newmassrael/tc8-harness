#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_mss_options_05_common.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_liveness.h"
#include "sce_integration/test_runner.h"

#include "tcp_mss_options_05_sm.h"

namespace tc8::sce::cases {

using TcpMssOptions05SM = ::SCE::Generated::tcp_mss_options_05::tcp_mss_options_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpMssOptions05SM>
    : TcpAnyBase<cases::TcpMssOptions05SM> {
    static constexpr std::string_view kCaseId       = "TCP_MSS_OPTIONS_05";
    static constexpr std::string_view kDescription  =
        "TCP MUST handle an illegal MSS option length in a SYN,ACK "
        "segment without crashing (RFC 1122 §4.2.2.5 p85). Iterations: "
        "ilen=0 and ilen=5.";

    // Each iteration holds the DUT's active open in SYN-SENT (no tester
    // listener) until the crafted SYN+ACK injection establishes it. The
    // testability CONNECT SP requires the handshake to establish and so cannot
    // hold a socket in SYN-SENT, while the opcode non-blocking worker can —
    // kCapTcpSynSentOpen makes the CLI capability gate honestly SKIP this case
    // on a testability backend (Tier 2 2b#4) instead of failing it. Whether
    // the DUT survived is graded by the liveness probe (dut_liveness.h), not
    // by a state query, which a crashed DUT could not answer.
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        ::tc8::sce::kCapTcpControl | ::tc8::sce::kCapTcpSynSentOpen;
    // The case's segments and the Echo Reply to its liveness probe.
    static constexpr ::tc8::BpfGroup kBpfGroup = ::tc8::BpfGroup::TcpAndIcmpv4;

    // The two iterations and their liveness probes
    // (_tcp_mss_options_05_common.h), with nothing armed between them.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::cases::mss_options_05::driveMssSynAckIterations(
            c, cfg, ctx, [] {}, [] {});
    }

    // The case grades only the DUT's answers to its liveness probes; its own TCP
    // segments are recorded in the pcap and bear on no transition.
    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const std::uint16_t seq = ::tc8::sce::liveness::livenessEchoReplySeq(ev, c.liveness_dut_ip);
        if (seq == 0U) return;
        c.liveness_echo_seq = seq;
        sm.raiseExternal(Event::Dut_echo_reply);
        sm.step();
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpMssOptions05SM, tcp_mss_options_05)
